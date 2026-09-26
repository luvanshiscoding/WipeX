import { defineConfig } from 'vite'

// Development: Vite serves the UI on :5173 and proxies /api to the backend on :8000.
// Production / offline: `npm run build` writes dist/, which the backend serves itself.
export default defineConfig({
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true
      }
    }
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    emptyOutDir: true
  }
})
