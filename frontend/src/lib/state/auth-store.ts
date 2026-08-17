// Client auth state (Zustand + localStorage persistence).
//
// Holds the token pair + cached user. Non-hook accessors (getToken /
// getRefreshToken / setTokens / clearToken) let the API client read and rotate
// tokens without React.

import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { UserOut } from '@/lib/api/types';

interface AuthState {
  token: string | null;
  refreshToken: string | null;
  user: UserOut | null;
  setAuth: (token: string, refreshToken: string | null, user?: UserOut | null) => void;
  setTokens: (token: string, refreshToken: string | null) => void;
  setUser: (user: UserOut | null) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      refreshToken: null,
      user: null,
      setAuth: (token, refreshToken, user = null) => set({ token, refreshToken, user }),
      // Used by the refresh path: replaces the pair but keeps the cached user, so
      // a token rotation does not flash the UI back to a logged-out state.
      setTokens: (token, refreshToken) => set({ token, refreshToken }),
      setUser: (user) => set({ user }),
      logout: () => set({ token: null, refreshToken: null, user: null }),
    }),
    { name: 'sephela-auth' },
  ),
);

// Non-reactive accessors used by the API client.
export function getToken(): string | null {
  return useAuthStore.getState().token;
}

export function getRefreshToken(): string | null {
  return useAuthStore.getState().refreshToken;
}

export function setTokens(token: string, refreshToken: string | null): void {
  useAuthStore.getState().setTokens(token, refreshToken);
}

export function clearToken(): void {
  useAuthStore.getState().logout();
}
