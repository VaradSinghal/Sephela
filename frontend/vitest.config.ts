/// <reference types="vitest" />
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  plugins: [react()],
  resolve: {
    // Mirrors the `@/*` path mapping in tsconfig.json. Kept in step by hand because
    // vite does not read tsconfig paths; a divergence shows up as an unresolved
    // import at test time rather than as a type error.
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./vitest.setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    // Each file gets a fresh module registry, so the zustand store — which is a
    // module-level singleton — cannot leak a logged-in session between files.
    isolate: true,
    restoreMocks: true,
  },
});
