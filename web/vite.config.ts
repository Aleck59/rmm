import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The build output goes straight into the Go server's embed directory. Using a
// relative base keeps asset URLs correct regardless of the host/port the
// server is reached on.
export default defineConfig({
  base: './',
  plugins: [react()],
  server: {
    // Local `pnpm dev` proxies API calls to a server running on :8080.
    proxy: {
      '/api': 'http://127.0.0.1:8080',
      '/healthz': 'http://127.0.0.1:8080',
      '/readyz': 'http://127.0.0.1:8080',
      '/version': 'http://127.0.0.1:8080',
    },
  },
  build: {
    outDir: '../internal/webui/dist',
    emptyOutDir: true,
  },
})
