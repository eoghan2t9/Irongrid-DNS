import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { visualizer } from 'rollup-plugin-visualizer'

export default defineConfig({
  plugins: [
    react(),
    // Optional bundle report: `REPORT=1 npm run build` writes dist/stats.html
    // (an interactive treemap of every chunk) so bundle growth is visible.
    ...(process.env.REPORT ? [visualizer({ gzipSize: true, filename: 'dist/stats.html' })] : []),
  ],
  // Relative base so the SPA works when served from any path behind the Go binary.
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      output: {
        // Keep the React runtime in its own long-cached chunk so app-code
        // changes don't invalidate the vendor bundle. (Vite 8's rolldown
        // engine only accepts the function form of manualChunks.)
        manualChunks(id) {
          if (
            id.includes('node_modules/react') ||
            id.includes('node_modules/react-dom') ||
            id.includes('node_modules/scheduler')
          ) {
            return 'react'
          }
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
  // Vitest: runs in jsdom against the same config as the dev/build toolchain.
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.js'],
    include: ['src/**/*.{test,spec}.{js,jsx}'],
  },
})
