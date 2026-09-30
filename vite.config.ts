import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: false,
    host: '127.0.0.1',
    // Dynamic HMR: avoids hardcoding port 1420 which causes infinite reconnect reload loops
    hmr: {
      protocol: 'ws',
      host: '127.0.0.1',
    },
    watch: {
      // Ignore Rust build artifacts, SQLite database files, video recordings, and exports
      ignored: [
        '**/src-tauri/**',
        '**/exports/**',
        '**/*.db*',
        '**/*.db-journal',
        '**/*.log',
        '**/*.mkv',
        '**/*.webm',
        '**/*.png',
        '**/videos/**',
      ],
    },
  },
})

