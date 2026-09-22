import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// base './' so the Go binary can serve dist/ from any path prefix.
export default defineConfig({
  base: './',
  plugins: [react()],
  build: { outDir: 'dist', emptyOutDir: true, sourcemap: false },
  server: {
    port: 5173,
    proxy: { '/v1': { target: 'http://localhost:8080', changeOrigin: false } },
  },
})
