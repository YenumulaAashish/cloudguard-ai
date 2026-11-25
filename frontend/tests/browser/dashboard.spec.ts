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
      await expect(page.getByText('LIVE CONNECTIVITY UNVERIFIED')).toBeVisible();
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


test('authenticated-origin import retains warnings and renders safe failed reasons', async ({page})=>{
  const fs=await import('node:fs/promises');const value=JSON.parse(await fs.readFile('src/test/plan-demo.json','utf8'));
  value.source=value.findings.source='AUTHENTICATED_PLAN';value.pr.policy.opa_conftest='FAIL';value.version='1.2';
  value.policy_reasons=[{rule_id:'UNKNOWN',reason_code:'UNRESOLVED_SECURITY_FIELD',count:1}];
  await page.goto('/');
  await page.getByLabel('Select sanitized report bundle').setInputFiles({name:'sanitized.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(value))});
  await expect(page.getByText('Imported authenticated-plan verdict · provenance unverified')).toBeVisible();
  await page.goto('/#/aws');await expect(page.getByText(/Authenticated-plan report supplied/)).toBeVisible();
  await expect(page.getByText('LIVE CONNECTIVITY UNVERIFIED')).toBeVisible();
  await page.goto('/#/scans');await expect(page.getByText(/UNRESOLVED_SECURITY_FIELD/)).toBeVisible();
});


test('Phase 6 operator preview, exact mock Deploy and drift alerts stay local',async({page})=>{
 const job={kind:'JOB',id:'00000000-0000-0000-0000-000000000001',purpose:'CONFIG',mode:'MOCK_ONLY',changes:{create:1,update:0,delete:0},gates:Object.fromEntries(['terraform_validate','checkov','opa','conftest','cost'].map(k=>[k,{status:'PASS',reason:k==='cost'?'WITHIN_MOCK_BUDGET':'MOCK_TEST_EVIDENCE'}])),cost:{status:'PASS',estimate_usd:'1.00',limit_usd:'5.00',mode:'MOCK_ONLY',reason:'WITHIN_MOCK_BUDGET'},created_at:Date.now()/1000,expires_at:Date.now()/1000+600,confirmation:'',context_reason:'KNOWN_MOCK_CONTEXT',status:'READY',can_deploy:true};
 let deployed=false;
 await page.route('**/api/phase6/**',async route=>{
  const action=route.request().url().split('/').pop();let data:unknown;
  if(action==='login')data={kind:'SESSION',authenticated:true,csrf:'csrf-fixture'};
  else if(action==='preview')data=job;
  else if(action==='deploy'){
   const body=route.request().postDataJSON();expect(Object.keys(body).sort()).toEqual(['confirmation','plan_id','request_id']);expect(body.plan_id).toBe(job.id);deployed=true;
   data={...job,status:'MOCK_SUCCEEDED',can_deploy:false};
  }else if(action==='status')data={kind:'STATUS',mode:'MOCK_ONLY',inventory:[],history:[{...job,status:'MOCK_SUCCEEDED',can_deploy:false}],audit:[],state_serial:1,busy:false,budget_limit_usd:'20.00'};
  else data={kind:'DRIFT',mode:'MOCK_ONLY',status:action==='simulate-drift'?'DRIFTED':'IN_SYNC',reason:'CONFIGURATION_COMPARISON_ONLY',changes:[],alerts:action==='simulate-drift'?[{id:'alert-1',kind:'DRIFTED',status:'OPEN'}]:[]};
  await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({mode:'MOCK_ONLY',ok:true,data})});
 });
 await page.goto('/#/provisioning');await expect(page.getByText(/MOCK ONLY/)).toBeVisible();
 await page.getByLabel('Operator secret').fill('synthetic-operator-secret-for-tests');await page.getByText('Sign in locally').click();
 await page.getByText('Generate and preview').click();await expect(page.getByText('Deploy mock plan')).toBeEnabled();await page.getByText('Deploy mock plan').click();
 await expect(page.getByText('MOCK_SUCCEEDED').first()).toBeVisible();expect(deployed).toBe(true);
 await page.getByText('Simulate changed control').click();await expect(page.getByText(/1 open alerts/)).toBeVisible();
});
