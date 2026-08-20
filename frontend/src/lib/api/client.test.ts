// The single choke point for every backend call, so its edge cases are everyone's
// edge cases. The refresh path gets the most attention: it is the only place in the
// client that can silently end a user's session, and the shared-in-flight-promise
// trick that stops five concurrent 401s from rotating the refresh token five times is
// invisible unless something asserts on it.

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api, ApiError } from './client';
import { useAuthStore } from '@/lib/state/auth-store';

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init,
  });
}

function problemResponse(status: number, problem: Record<string, unknown>): Response {
  return new Response(JSON.stringify(problem), {
    status,
    headers: { 'content-type': 'application/problem+json' },
  });
}

/** Install a fetch stub and return the recorded calls. */
function stubFetch(...responses: Array<Response | (() => Response | Promise<Response>)>) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  let index = 0;
  const fetchMock = vi.fn(async (url: string | URL, init: RequestInit = {}) => {
    calls.push({ url: String(url), init });
    const next = responses[Math.min(index, responses.length - 1)];
    index += 1;
    return typeof next === 'function' ? next() : next.clone();
  });
  vi.stubGlobal('fetch', fetchMock);
  return calls;
}

/** Read a Blob as text. jsdom's Blob implements neither `.text()` nor undici's. */
function readBlob(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(blob);
  });
}

beforeEach(() => {
  useAuthStore.getState().logout();
});

describe('request construction', () => {
  it('prefixes every path with the versioned API base', async () => {
    const calls = stubFetch(jsonResponse({ ok: true }));

    await api.get('/jobs');

    expect(calls[0].url).toBe('/api/v1/jobs');
  });

  it('attaches the bearer token when one is stored', async () => {
    useAuthStore.getState().setAuth('access-abc', 'refresh-xyz');
    const calls = stubFetch(jsonResponse({}));

    await api.get('/jobs');

    expect(new Headers(calls[0].init.headers).get('authorization')).toBe('Bearer access-abc');
  });

  it('sends no authorization header when there is no token', async () => {
    const calls = stubFetch(jsonResponse({}));

    await api.get('/jobs');

    expect(new Headers(calls[0].init.headers).has('authorization')).toBe(false);
  });

  it('omits the token when a call opts out of auth', async () => {
    // Login is the case: sending a stale token to /auth/login would be answered with
    // a 401 the refresh path would then try to recover from.
    useAuthStore.getState().setAuth('access-abc', 'refresh-xyz');
    const calls = stubFetch(jsonResponse({}));

    await api.post('/auth/login', { email: 'a@b.c' }, { auth: false });

    expect(new Headers(calls[0].init.headers).has('authorization')).toBe(false);
  });

  it('serialises a JSON body and sets its content type', async () => {
    const calls = stubFetch(jsonResponse({}));

    await api.post('/jobs', { sample: 'x' });

    expect(calls[0].init.body).toBe('{"sample":"x"}');
    expect(new Headers(calls[0].init.headers).get('content-type')).toBe('application/json');
  });

  it('passes FormData through without a content type', async () => {
    // The browser has to set the multipart boundary itself; overriding the header
    // produces a body the server cannot parse.
    const form = new FormData();
    form.set('file', new Blob([new Uint8Array([1, 2])]), 'sample.apk');
    const calls = stubFetch(jsonResponse({}));

    await api.post('/uploads', form);

    expect(calls[0].init.body).toBeInstanceOf(FormData);
    expect(new Headers(calls[0].init.headers).has('content-type')).toBe(false);
  });

  it('sends no body and no content type for a GET', async () => {
    const calls = stubFetch(jsonResponse({}));

    await api.get('/jobs');

    expect(calls[0].init.body).toBeUndefined();
    expect(new Headers(calls[0].init.headers).has('content-type')).toBe(false);
  });
});

describe('response handling', () => {
  it('parses a JSON body', async () => {
    stubFetch(jsonResponse({ job_id: 'j-1' }));

    await expect(api.get<{ job_id: string }>('/jobs/j-1')).resolves.toEqual({ job_id: 'j-1' });
  });

  it('returns text when the response is not JSON', async () => {
    stubFetch(new Response('plain', { status: 200, headers: { 'content-type': 'text/plain' } }));

    await expect(api.get<string>('/thing')).resolves.toBe('plain');
  });

  it('resolves to undefined for a 204', async () => {
    stubFetch(new Response(null, { status: 204 }));

    await expect(api.del('/jobs/j-1')).resolves.toBeUndefined();
  });
});

describe('error normalisation', () => {
  it('raises the problem detail as the message', async () => {
    // RFC 9457 `detail` is written for a human, which is what the UI renders.
    stubFetch(problemResponse(422, { title: 'Validation error', detail: 'Not an APK.' }));

    await expect(api.post('/uploads', {})).rejects.toThrow('Not an APK.');
  });

  it('falls back to the title when there is no detail', async () => {
    stubFetch(problemResponse(422, { title: 'Validation error' }));

    await expect(api.post('/uploads', {})).rejects.toThrow('Validation error');
  });

  it('falls back to the status text when the body is not a problem document', async () => {
    stubFetch(new Response('<html>502</html>', { status: 502, statusText: 'Bad Gateway' }));

    await expect(api.get('/jobs')).rejects.toThrow('Bad Gateway');
  });

  it('carries the status and the trace id for support', async () => {
    // The trace id is what ties a user's screenshot to a log line.
    stubFetch(problemResponse(500, { detail: 'boom', trace_id: 'trace-42' }));

    const error = await api.get('/jobs').catch((e: unknown) => e as ApiError);

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(500);
    expect((error as ApiError).traceId).toBe('trace-42');
  });

  it('reports a network failure as status zero rather than leaking the fetch error', async () => {
    // A TypeError from fetch reaching a React error boundary is unreadable; the UI
    // distinguishes "cannot reach the server" from "the server said no" on this.
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch');
      }),
    );

    const error = await api.get('/jobs').catch((e: unknown) => e as ApiError);

    expect((error as ApiError).status).toBe(0);
    expect((error as ApiError).message).toMatch(/could not reach the server/i);
  });

  it('leaves the trace id null when the server sent none', async () => {
    stubFetch(problemResponse(400, { detail: 'bad' }));

    const error = await api.get('/jobs').catch((e: unknown) => e as ApiError);

    expect((error as ApiError).traceId).toBeNull();
  });
});

describe('token refresh', () => {
  it('refreshes and replays the request on a 401', async () => {
    // An expired access token is the common case, not a session failure.
    useAuthStore.getState().setAuth('expired', 'refresh-1');
    const calls = stubFetch(
      new Response(null, { status: 401 }),
      jsonResponse({ access_token: 'fresh', refresh_token: 'refresh-2' }),
      jsonResponse({ job_id: 'j-1' }),
    );

    await expect(api.get<{ job_id: string }>('/jobs/j-1')).resolves.toEqual({ job_id: 'j-1' });

    expect(calls.map((c) => c.url)).toEqual([
      '/api/v1/jobs/j-1',
      '/api/v1/auth/refresh',
      '/api/v1/jobs/j-1',
    ]);
  });

  it('stores the rotated refresh token', async () => {
    // Rotation is unconditional server-side, so keeping the old one would make the
    // next refresh fail against a spent token.
    useAuthStore.getState().setAuth('expired', 'refresh-1');
    stubFetch(
      new Response(null, { status: 401 }),
      jsonResponse({ access_token: 'fresh', refresh_token: 'refresh-2' }),
      jsonResponse({}),
    );

    await api.get('/jobs');

    expect(useAuthStore.getState().token).toBe('fresh');
    expect(useAuthStore.getState().refreshToken).toBe('refresh-2');
  });

  it('replays with the new access token, not the expired one', async () => {
    useAuthStore.getState().setAuth('expired', 'refresh-1');
    const calls = stubFetch(
      new Response(null, { status: 401 }),
      jsonResponse({ access_token: 'fresh', refresh_token: 'refresh-2' }),
      jsonResponse({}),
    );

    await api.get('/jobs');

    expect(new Headers(calls[2].init.headers).get('authorization')).toBe('Bearer fresh');
  });

  it('keeps the cached user across a rotation', async () => {
    // Otherwise a background refresh flashes the UI back to a logged-out state.
    const user = { id: 'u-1', email: 'a@b.c' } as never;
    useAuthStore.getState().setAuth('expired', 'refresh-1', user);
    stubFetch(
      new Response(null, { status: 401 }),
      jsonResponse({ access_token: 'fresh', refresh_token: 'refresh-2' }),
      jsonResponse({}),
    );

    await api.get('/jobs');

    expect(useAuthStore.getState().user).toEqual(user);
  });

  it('clears the session when the refresh itself is rejected', async () => {
    // Only now is the session genuinely over.
    useAuthStore.getState().setAuth('expired', 'spent');
    stubFetch(new Response(null, { status: 401 }), new Response(null, { status: 401 }));

    await expect(api.get('/jobs')).rejects.toBeInstanceOf(ApiError);

    expect(useAuthStore.getState().token).toBeNull();
  });

  it('does not attempt a refresh without a refresh token', async () => {
    useAuthStore.getState().setAuth('access-only', null);
    const calls = stubFetch(new Response(null, { status: 401 }));

    await expect(api.get('/jobs')).rejects.toBeInstanceOf(ApiError);

    expect(calls.map((c) => c.url)).toEqual(['/api/v1/jobs']);
  });

  it('does not attempt a refresh for an unauthenticated call', async () => {
    // A 401 from /auth/login means the password was wrong, and refreshing would both
    // fail and clear a session the user may still have.
    useAuthStore.getState().setAuth('access', 'refresh-1');
    const calls = stubFetch(problemResponse(401, { detail: 'Invalid credentials' }));

    await expect(api.post('/auth/login', {}, { auth: false })).rejects.toThrow(
      'Invalid credentials',
    );

    expect(calls).toHaveLength(1);
    expect(useAuthStore.getState().token).toBe('access');
  });

  it('shares one refresh across concurrent 401s', async () => {
    // Five queries firing on an expired token must rotate once. Rotating five times
    // would invalidate the session the first rotation just established.
    useAuthStore.getState().setAuth('expired', 'refresh-1');
    let refreshCalls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const path = String(url);
        if (path.endsWith('/auth/refresh')) {
          refreshCalls += 1;
          await new Promise((resolve) => setTimeout(resolve, 5));
          return jsonResponse({ access_token: 'fresh', refresh_token: 'refresh-2' });
        }
        if (useAuthStore.getState().token === 'expired') {
          return new Response(null, { status: 401 });
        }
        return jsonResponse({ ok: true });
      }),
    );

    await Promise.all([
      api.get('/jobs'),
      api.get('/jobs'),
      api.get('/jobs'),
      api.get('/jobs'),
      api.get('/jobs'),
    ]);

    expect(refreshCalls).toBe(1);
  });

  it('does not retry more than once', async () => {
    // A server that 401s a freshly issued token would otherwise loop.
    useAuthStore.getState().setAuth('expired', 'refresh-1');
    const calls = stubFetch(
      new Response(null, { status: 401 }),
      jsonResponse({ access_token: 'fresh', refresh_token: 'refresh-2' }),
      new Response(null, { status: 401 }),
    );

    await expect(api.get('/jobs')).rejects.toBeInstanceOf(ApiError);

    expect(calls).toHaveLength(3);
    expect(useAuthStore.getState().token).toBeNull();
  });
});

describe('blob downloads', () => {
  it('returns the bytes and the server-chosen filename', async () => {
    // The filename comes from the server because it encodes the job and format; a
    // client-side guess would produce files an analyst cannot tell apart.
    stubFetch(
      new Response('report-bytes', {
        status: 200,
        headers: {
          'content-type': 'application/pdf',
          'content-disposition': 'attachment; filename="sephela-j1.pdf"',
        },
      }),
    );

    const { blob, filename } = await api.blob('/jobs/j-1/report/pdf');

    expect(filename).toBe('sephela-j1.pdf');
    expect(await readBlob(blob)).toBe('report-bytes');
    expect(blob.type).toBe('application/pdf');
  });

  it('parses an unquoted filename', async () => {
    stubFetch(
      new Response('x', {
        status: 200,
        headers: { 'content-disposition': 'attachment; filename=report.json' },
      }),
    );

    expect((await api.blob('/jobs/j-1/report/json')).filename).toBe('report.json');
  });

  it('returns a null filename when the header is absent', async () => {
    stubFetch(new Response('x', { status: 200 }));

    expect((await api.blob('/jobs/j-1/report/json')).filename).toBeNull();
  });

  it('raises rather than handing back an error page as a download', async () => {
    // Saving a 500 HTML body as report.pdf is worse than failing loudly.
    stubFetch(problemResponse(404, { detail: 'Report not rendered.' }));

    await expect(api.blob('/jobs/j-1/report/pdf')).rejects.toThrow('Report not rendered.');
  });
});
