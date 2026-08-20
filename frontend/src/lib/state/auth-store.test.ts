// The token pair plus the cached user. The non-hook accessors exist so the API client
// can rotate tokens without React, which means this store is mutated from two
// directions and its invariants are worth stating.

import { beforeEach, describe, expect, it } from 'vitest';
import { clearToken, getRefreshToken, getToken, setTokens, useAuthStore } from './auth-store';
import type { UserOut } from '@/lib/api/types';

const USER = {
  id: 'u-1',
  email: 'analyst@bank.example',
  role: 'analyst',
  org_id: 'o-1',
} as unknown as UserOut;

beforeEach(() => {
  useAuthStore.getState().logout();
});

describe('initial state', () => {
  it('starts logged out', () => {
    expect(getToken()).toBeNull();
    expect(getRefreshToken()).toBeNull();
    expect(useAuthStore.getState().user).toBeNull();
  });
});

describe('setAuth', () => {
  it('stores the pair and the user', () => {
    useAuthStore.getState().setAuth('access-1', 'refresh-1', USER);

    expect(getToken()).toBe('access-1');
    expect(getRefreshToken()).toBe('refresh-1');
    expect(useAuthStore.getState().user).toEqual(USER);
  });

  it('defaults the user to null when the caller has not fetched it yet', () => {
    useAuthStore.getState().setAuth('access-1', 'refresh-1');

    expect(useAuthStore.getState().user).toBeNull();
  });

  it('accepts a null refresh token', () => {
    useAuthStore.getState().setAuth('access-1', null);

    expect(getRefreshToken()).toBeNull();
  });
});

describe('setTokens', () => {
  it('replaces the pair', () => {
    useAuthStore.getState().setAuth('access-1', 'refresh-1', USER);

    setTokens('access-2', 'refresh-2');

    expect(getToken()).toBe('access-2');
    expect(getRefreshToken()).toBe('refresh-2');
  });

  it('keeps the cached user', () => {
    // The refresh path calls this. Clearing the user would flash the UI back to a
    // logged-out state on every silent rotation.
    useAuthStore.getState().setAuth('access-1', 'refresh-1', USER);

    setTokens('access-2', 'refresh-2');

    expect(useAuthStore.getState().user).toEqual(USER);
  });
});

describe('logout', () => {
  it('clears everything', () => {
    useAuthStore.getState().setAuth('access-1', 'refresh-1', USER);

    useAuthStore.getState().logout();

    expect(getToken()).toBeNull();
    expect(getRefreshToken()).toBeNull();
    expect(useAuthStore.getState().user).toBeNull();
  });

  it('clears the cached user too, not just the tokens', () => {
    // A stale user surviving a logout would show the previous analyst's name and org
    // to whoever logs in next — on a per-tenant platform that is a disclosure.
    useAuthStore.getState().setAuth('access-1', 'refresh-1', USER);

    clearToken();

    expect(useAuthStore.getState().user).toBeNull();
  });

  it('is safe to call when already logged out', () => {
    clearToken();
    clearToken();

    expect(getToken()).toBeNull();
  });
});

describe('persistence', () => {
  it('writes the session to localStorage under a namespaced key', () => {
    useAuthStore.getState().setAuth('access-1', 'refresh-1', USER);

    const raw = window.localStorage.getItem('sephela-auth');

    expect(raw).toBeTruthy();
    expect(JSON.parse(raw as string).state.token).toBe('access-1');
  });

  it('a logout is persisted, not just held in memory', () => {
    // Otherwise a reload after logging out restores the session.
    useAuthStore.getState().setAuth('access-1', 'refresh-1', USER);
    useAuthStore.getState().logout();

    const raw = window.localStorage.getItem('sephela-auth');

    expect(JSON.parse(raw as string).state.token).toBeNull();
  });

  it('persists the rotated pair from setTokens', () => {
    useAuthStore.getState().setAuth('access-1', 'refresh-1', USER);
    setTokens('access-2', 'refresh-2');

    const state = JSON.parse(window.localStorage.getItem('sephela-auth') as string).state;

    expect(state.refreshToken).toBe('refresh-2');
  });
});

describe('non-hook accessors', () => {
  it('read the same state the hook does', () => {
    // The API client uses these outside React; a divergence would have it sign requests
    // with a token the UI thinks it already replaced.
    useAuthStore.getState().setAuth('access-1', 'refresh-1', USER);

    expect(getToken()).toBe(useAuthStore.getState().token);
    expect(getRefreshToken()).toBe(useAuthStore.getState().refreshToken);
  });

  it('see a change made through the hook immediately', () => {
    useAuthStore.getState().setAuth('access-1', 'refresh-1');
    useAuthStore.setState({ token: 'changed' });

    expect(getToken()).toBe('changed');
  });
});
