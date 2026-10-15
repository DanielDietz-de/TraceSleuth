/// <reference types="vitest" />
import { readFileSync } from 'node:fs'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Keep browser version metadata tied to the authoritative repository VERSION.
// Avoid the inherited frontend package.json version, which is not a product version.
const tracesleuthVersion = readFileSync(new URL('../../VERSION', import.meta.url), 'utf8').trim()
if (!/^\d+\.\d+\.\d+$/.test(tracesleuthVersion)) {
  throw new Error('Invalid authoritative TraceSleuth VERSION')
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  define: {
    __TRACESLEUTH_VERSION__: JSON.stringify(tracesleuthVersion),
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api/ws': {
        target: 'http://127.0.0.1:8080',
        // Preserve the browser Host for exact same-origin WS verification.
        // HTTP /api requests may still rewrite Host independently.
        changeOrigin: false,
        ws: true,
      },
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
        timeout: 300000, // 5 min timeout for large uploads
      },
    },
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: false,
    minify: 'esbuild',
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
        },
      },
    },
  },
})
