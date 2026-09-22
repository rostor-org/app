import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Served at the root by the Go binary, which falls back to index.html for
// unknown paths, so history routing and deep links work.
export default defineConfig({
  base: '/',
  plugins: [react()],
  build: { outDir: 'dist', emptyOutDir: true, sourcemap: false },
  server: {
    port: 5173,
    proxy: { '/v1': { target: 'http://localhost:8080', changeOrigin: false } },
  },
})
