import { test, expect } from '@playwright/test';

test('all pages render, filters operate, no external requests or browser errors', async ({ page }) => {
  const errors: string[] = [], external: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', async route => {
    if (new URL(route.request().url()).hostname !== '127.0.0.1') { external.push('Unexpected external request'); await route.abort(); }
    else await route.continue();
  });
  await page.setViewportSize({ width: 1440, height: 1150 });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Security overview' })).toBeVisible();
  await expect(page.getByTestId('risk-score')).toHaveText('13');
  await page.screenshot({ path: 'test-results/overview-desktop.png', fullPage: true });
  for (const [path, title] of [['findings', 'Findings'], ['posture', 'Cloud posture'], ['risk', 'Risk analysis'], ['graph', 'Security graph'], ['advisory', 'AI advisory'], ['scans', 'CI / scan status'], ['aws', 'AWS integration']]) {
    await page.goto(`/#/${path}`);
    await expect(page.getByRole('heading', { name: title, exact: true })).toBeVisible();
  }
  await page.goto('/#/findings');
  await page.getByLabel('Domain', { exact: true }).selectOption('IAM');
  await page.getByLabel('Severity', { exact: true }).selectOption('CRITICAL');
  await expect(page.getByText('1 groups shown')).toBeVisible();
  await page.getByLabel('Select sanitized report bundle').setInputFiles({ name: 'invalid.json', mimeType: 'application/json', buffer: Buffer.from('{"secret":"PRIVATE_CANARY"}') });
  await expect(page.getByText('Report rejected')).toBeVisible();
  await expect(page.getByText('PRIVATE_CANARY')).toHaveCount(0);
  await page.getByRole('button', { name: 'Reset demo' }).click();
  await expect(page.getByRole('heading', { name: 'Finding groups' })).toBeVisible();
  expect(errors).toEqual([]); expect(external).toEqual([]);
});

test('mobile and tablet layouts remain usable without horizontal overflow', async ({ page }) => {
  for (const width of [390, 820]) {
    await page.setViewportSize({ width, height: 900 }); await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Security overview' })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    if (width < 700) {
      await page.getByRole('button', { name: 'Open navigation' }).click();
      await page.getByRole('navigation').getByRole('link', { name: 'AWS Integration' }).click();
      await expect(page.getByText('WAITING FOR AWS VERIFICATION')).toBeVisible();
      await page.goto('/');
    }
    await page.screenshot({ path: `test-results/overview-${width}.png`, fullPage: true });
  }
});

test('dev server blocks repository files', async ({ request }) => {
  // A known non-sensitive repository file is the canary for the filesystem boundary.
  const response = await request.get('/@fs/' + process.cwd().replaceAll('\\', '/').replace(/\/frontend$/, '') + '/README.md');
  expect(response.status()).toBe(403);
});
