import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// NOTE: `host: '0.0.0.0'` + `allowedHosts: true` are required so the dev
// server is reachable through the sandbox preview proxy
// (https://{port}-{sandboxId}.e2b.app). Do not tighten these without also
// adding the preview host pattern.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: false,
    allowedHosts: true,
  },
  preview: {
    host: '0.0.0.0',
    port: 4173,
    allowedHosts: true,
  },
});
