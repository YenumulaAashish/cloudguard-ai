import { readFileSync, readdirSync, existsSync, lstatSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, relative, extname } from 'node:path';
import assert from 'node:assert/strict';
import Ajv2020 from 'ajv/dist/2020.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const read = name => readFileSync(resolve(root, name), 'utf8');
const schemas = JSON.parse(read('src/data/contracts.json'));
const names = { pr: 'pr-summary', phase3: 'phase3-evidence', posture: 'cloud-posture-summary', phase4: 'phase4-completion' };
for (const [key, name] of Object.entries(names)) {
  assert.deepEqual(schemas[key], JSON.parse(read(`../security/${name}.schema.json`)), 'Public schema must match the engine contract');
}
// Validate data before it can be bundled: hiding a rejected value in React is
// insufficient because a malicious extra field would still exist in the asset.
const demo = JSON.parse(read('src/data/demo.json'));
assert.deepEqual(Object.keys(demo).sort(), ['version', 'source', ...Object.keys(names)].sort(), 'Unexpected bundle field');
assert.equal(demo.version, '1.0');
assert.equal(demo.source, 'OFFLINE_SYNTHETIC');
assert.equal(demo.pr.policy.opa_conftest, 'UNKNOWN', 'Offline snapshot cannot attest a real-plan verdict');
const validator = new Ajv2020({ strict: true });
for (const key of Object.keys(names)) {
  assert(validator.compile(schemas[key])(demo[key]), 'Demo data violates public contract (values withheld)');
  assert(Buffer.byteLength(JSON.stringify(demo[key])) <= 4096, 'Public data too large');
}
assert(!existsSync(resolve(root, 'public')), 'No unchecked public asset directory allowed');
const pkg = JSON.parse(read('package.json'));
for (const version of Object.values({ ...pkg.dependencies, ...pkg.devDependencies })) {
  assert(/^\d+\.\d+\.\d+$/.test(version), 'Dependencies must use exact versions');
}
const forbiddenContent = [
  /(?:AKIA|ASIA)[A-Z0-9]{16}/,
  /(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /(?:aws_secret_access_key|aws_access_key_id|api_key|device_token|client_secret|access_token|refresh_token)["']?\s*[:=]\s*["'][^"']{8,}/i,
  /arn:aws(?:-[a-z]+)?:[a-z0-9-]+:/,
  /"(?:planned_values|resource_changes|terraform_version|report_fingerprints|finding_associations|prior_state|deposed)"\s*:/,
  /reports[\\/]private[\\/]/,
];
function scan(folder) {
  for (const entry of readdirSync(folder, { withFileTypes: true })) {
    const path = resolve(folder, entry.name);
    assert(!lstatSync(path).isSymbolicLink(), 'Served inputs must not be symlinks');
    if (entry.isDirectory()) { scan(path); continue; }
    if (entry.name.includes('.test.') || relative(root, path).startsWith('src' + (process.platform === 'win32' ? '\\' : '/') + 'test')) continue;
    assert(!/\.env|\.tfstate|\.tfplan|^tfplan|\.pem$|\.key$|\.map$/.test(entry.name), 'Private file type in frontend');
    assert(['.ts', '.tsx', '.json', '.css', '.js', '.html'].includes(extname(path)), 'Unreviewed served file type');
    const text = readFileSync(path, 'utf8');
    for (const pattern of forbiddenContent) assert(!pattern.test(text), `Sensitive marker in ${relative(root, path)} (value withheld)`);
    if (path.includes(`${process.platform === 'win32' ? '\\' : '/'}src`) && /\.(ts|tsx)$/.test(path)) {
      assert(!/\b(?:fetch|XMLHttpRequest|WebSocket|EventSource)\s*\(/.test(text), 'No outbound frontend transport allowed');
      assert(!/import\.meta\.env|process\.env|dangerouslySetInnerHTML/.test(text), 'No environment or raw HTML injection allowed');
      assert(!/(?:from\s*|import\s*)['"](?:\.\.\/){3}/.test(text), 'Source import escapes frontend');
    }
  }
}
try {
  scan(resolve(root, 'src'));
  if (existsSync(resolve(root, 'dist'))) scan(resolve(root, 'dist'));
  console.log('Frontend privacy checks: PASS (closed schema parity, exact dependencies, source/assets and built output)');
} catch {
  console.error('Frontend privacy checks: FAIL; inspect local files. Values withheld.');
  process.exitCode = 1;
}
