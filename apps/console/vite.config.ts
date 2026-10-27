// The console's build (6A1): static files the API serves from the same origin
// (apps/api/src/console-files.ts). The API's CSP is `default-src 'self';
// script-src 'self'`, so nothing may be inlined: no small asset turned into a
// data: URL, no inline module-preload polyfill. Every asset lands in
// `assets/` under a hashed name, the one shape the API serves.
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    assetsDir: 'assets',
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
    target: 'es2022',
  },
});
