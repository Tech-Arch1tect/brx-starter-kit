import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'public/build',
    manifest: true,
    rollupOptions: {
      input: {
        app: 'resources/js/app.tsx'
      }
    }
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    cors: true,
  }
})