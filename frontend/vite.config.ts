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
    rollupOptions: {
      output: {
        manualChunks: {
          three: ['three', '@react-three/fiber', '@react-three/drei', '@react-three/postprocessing'],
          reactflow: ['reactflow'],
          vendor: ['react', 'react-dom', 'react-router-dom', '@tanstack/react-query'],
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
