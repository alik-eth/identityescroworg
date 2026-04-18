import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

export default defineConfig({
  base: process.env.VITE_BASE ?? './',
  plugins: [
    react(),
    tailwindcss(),
    nodePolyfills({ include: ['buffer'], globals: { Buffer: true } }),
  ],
  build: {
    target: 'es2022',
  },
  optimizeDeps: {
    exclude: ['snarkjs'],
  },
  worker: {
    format: 'es',
  },
});
