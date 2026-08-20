import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, beforeEach } from 'vitest';

// jsdom gives us `sessionStorage` but not `localStorage`. Node 22+ defines its own
// `globalThis.localStorage`, which is undefined unless the process was started with
// `--localstorage-file`, and it shadows the one jsdom would otherwise install — so the
// property is simply absent here.
//
// The auth store persists through `localStorage`, so tests need a real one rather than
// a mock: zustand's `persist` reads it during module initialisation, before any test
// body runs. This is the standard Storage contract, in memory.
if (typeof window.localStorage === 'undefined') {
  const entries = new Map<string, string>();
  const storage: Storage = {
    get length() {
      return entries.size;
    },
    key: (index) => [...entries.keys()][index] ?? null,
    getItem: (key) => entries.get(String(key)) ?? null,
    setItem: (key, value) => void entries.set(String(key), String(value)),
    removeItem: (key) => void entries.delete(String(key)),
    clear: () => entries.clear(),
  };
  Object.defineProperty(window, 'localStorage', { value: storage, configurable: true });
  Object.defineProperty(globalThis, 'localStorage', { value: storage, configurable: true });
}

afterEach(() => {
  cleanup();
});

beforeEach(() => {
  // Without this, a test that logs in leaves the next one authenticated.
  window.localStorage.clear();
});
