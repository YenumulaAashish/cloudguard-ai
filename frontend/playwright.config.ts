import { defineConfig } from '@playwright/test';
const port = Number(process.env.CLOUDGUARD_TEST_PORT ?? 5173);
export default defineConfig({
  testDir: './tests/browser',
  use: { baseURL: `http://127.0.0.1:${port}`, channel: 'chrome', headless: true },
  webServer: { command: `npm run dev -- --port ${port} --strictPort`, url: `http://127.0.0.1:${port}`, reuseExistingServer: false },
  reporter: 'list',
});
