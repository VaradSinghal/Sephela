// Typed fetch wrapper — the single choke point for all backend calls.
//
// Responsibilities: base URL, auth header injection, JSON handling, transparent
// access-token refresh, and normalizing RFC 9457 Problem Details into a throwable
// ApiError so React Query + error boundaries get consistent errors.

import { getRefreshToken, getToken, clearToken, setTokens } from '@/lib/state/auth-store';
import type { ProblemDetails, Token } from './types';

const BASE = '/api/v1';

export class ApiError extends Error {
  status: number;
  problem?: ProblemDetails;
  traceId?: string | null;

  constructor(message: string, status: number, problem?: ProblemDetails) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.problem = problem;
    this.traceId = problem?.trace_id ?? null;
  }
}

interface RequestOptions extends Omit<RequestInit, 'body'> {
  body?: unknown;
  auth?: boolean; // attach bearer token (default true)
  raw?: boolean; // resolve to the Response rather than parsing a body
}

// A single in-flight refresh shared by every concurrent 401. Without this, a page
// that fires five queries at once on an expired token would rotate the refresh
// token five times and invalidate its own session.
let refreshing: Promise<boolean> | null = null;

async function refreshAccessToken(): Promise<boolean> {
  const token = getRefreshToken();
  if (!token) return false;

  try {
    const res = await fetch(`${BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: token }),
    });
    if (!res.ok) return false;
    const next = (await res.json()) as Token;
    // Rotation is unconditional server-side, so the new refresh token must be
    // stored or the next refresh fails against a spent one.
    setTokens(next.access_token, next.refresh_token);
    return true;
  } catch {
    return false;
  }
}

async function attemptRefresh(): Promise<boolean> {
  refreshing ??= refreshAccessToken().finally(() => {
    refreshing = null;
  });
  return refreshing;
}

async function send(path: string, opts: RequestOptions): Promise<Response> {
  const { body, auth = true, headers, raw: _raw, ...rest } = opts;

  const finalHeaders = new Headers(headers);
  const isFormData = body instanceof FormData;
  if (body !== undefined && !isFormData) {
    finalHeaders.set('Content-Type', 'application/json');
  }
  if (auth) {
    const token = getToken();
    if (token) finalHeaders.set('Authorization', `Bearer ${token}`);
  }

  return fetch(`${BASE}${path}`, {
    ...rest,
    headers: finalHeaders,
    body: isFormData ? (body as FormData) : body !== undefined ? JSON.stringify(body) : undefined,
  });
}

async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const { auth = true, raw = false } = opts;

  let res: Response;
  try {
    res = await send(path, opts);
  } catch {
    throw new ApiError('Network error — could not reach the server.', 0);
  }

  // An expired access token is the common case, not a session failure: try one
  // refresh and replay before giving up. Only if the refresh itself fails is the
  // session genuinely over.
  if (res.status === 401 && auth) {
    if (await attemptRefresh()) {
      try {
        res = await send(path, opts);
      } catch {
        throw new ApiError('Network error — could not reach the server.', 0);
      }
    }
    if (res.status === 401) clearToken();
  }

  const contentType = res.headers.get('content-type') ?? '';
  const isJson = contentType.includes('json');

  if (!res.ok) {
    const problem = isJson ? ((await res.json()) as ProblemDetails) : undefined;
    throw new ApiError(problem?.detail ?? problem?.title ?? res.statusText, res.status, problem);
  }

  if (raw) return res as unknown as T;
  if (res.status === 204) return undefined as T;
  return (isJson ? await res.json() : await res.text()) as T;
}

export const api = {
  get: <T>(path: string, opts?: RequestOptions) => request<T>(path, { ...opts, method: 'GET' }),
  post: <T>(path: string, body?: unknown, opts?: RequestOptions) =>
    request<T>(path, { ...opts, method: 'POST', body }),
  del: <T>(path: string, opts?: RequestOptions) => request<T>(path, { ...opts, method: 'DELETE' }),
  /** Fetch binary content (report artifacts) with auth applied. */
  blob: async (path: string): Promise<{ blob: Blob; filename: string | null }> => {
    const res = await request<Response>(path, { method: 'GET', raw: true });
    return { blob: await res.blob(), filename: filenameFrom(res) };
  },
};

/** Pull the server-chosen filename out of Content-Disposition, if present. */
function filenameFrom(res: Response): string | null {
  const header = res.headers.get('content-disposition') ?? '';
  const match = /filename="?([^";]+)"?/.exec(header);
  return match ? match[1] : null;
}
