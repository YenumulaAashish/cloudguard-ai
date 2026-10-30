import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Never serve the repository root, reports, plans, or environment files.
  publicDir: false,
  envDir: fileURLToPath(new URL('./disabled-environment', import.meta.url)),
  envPrefix: 'CLOUDGUARD_NO_BROWSER_ENV_',
  server: { host: '127.0.0.1', fs: { strict: true, allow: [root], deny: ['**/.env*', '**/*.tfstate*', '**/tfplan*'] } },
  build: { sourcemap: false, target: 'es2022', rollupOptions: {
    output: { manualChunks: { charts: ['recharts'], validation: ['ajv/dist/2020'] } },
  } },
  test: { environment: 'jsdom', setupFiles: ['./src/test/setup.ts'], include: ['src/**/*.test.{ts,tsx}'], restoreMocks: true },
});
