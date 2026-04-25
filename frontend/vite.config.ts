/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/socket.io': {
        target: 'http://localhost:8000',
        ws: true,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    // Split vendor chunks so the three.js + postprocessing payload (~600 kB
    // gzipped) loads lazily alongside GridSphere instead of blocking the
    // initial app shell. React + ReactFlow ship on first paint; three only
    // downloads when the user opens the topology page.
    //
    // Vite 8 swapped Rollup for Rolldown, which requires `manualChunks` to
    // be a function (the object-shorthand form was a Rollup-only sugar).
    // We rebuild the same buckets via id-substring matching so the output
    // chunk graph stays identical.
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (
              id.includes('/three/') ||
              id.includes('/@react-three/')
            ) return 'three'
            if (id.includes('/reactflow/') || id.includes('/@reactflow/')) return 'reactflow'
            if (
              id.includes('/react/') ||
              id.includes('/react-dom/') ||
              id.includes('/react-router-dom/') ||
              id.includes('/@tanstack/react-query/')
            ) return 'vendor'
          }
          return undefined
        },
      },
    },
    chunkSizeWarningLimit: 800,
  },
  test: {
    // jsdom gives us window/document for component tests. Happy-dom is
    // faster but stumbles on framer-motion's measurement observers.
    environment: 'jsdom',
    globals: true,
    // Setup file wires up @testing-library/jest-dom matchers and
    // silences known-noisy console errors (React 18 act() warnings
    // from framer-motion in jsdom, etc).
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    // Don't pick up Vite's own deps. The exclude list mirrors vitest's
    // defaults plus the three.js build dir so we never scan the
    // compiled vendor chunk.
    exclude: ['node_modules', 'dist', 'build'],
    // Mock the three.js + reactflow modules wholesale in component
    // tests — we're not rendering canvas/WebGL or topology graphs in
    // the headless test runner.
    server: {
      deps: {
        inline: ['reactflow'],
      },
    },
  },
})
