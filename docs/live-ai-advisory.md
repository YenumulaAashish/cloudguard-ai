# Live OpenAI advisory

Phase 5 update: the optional server-side `CLOUDGUARD_CATALOG_PATH` now accepts a
reviewed completed sanitized dashboard bundle, including actual plan findings.
The new contract and revision-bound requests are documented in
[Phase 5 integration](phase5-integration.md). The synthetic-only statements below
describe the original checkpoint. Existing API key, rate, authority and privacy
boundaries remain applicable; paid execution is still not claimed by local tests.

Deterministic tools decide. AI explains. The advisory service cannot modify reports,
scores, severity, status, exceptions, policies, CI outcomes or deployment decisions.
Its output has a separate `advisory` namespace and rejects all other fields.

```text
Existing synthetic fixture → deterministic analyzers → five-field projection
→ loopback Python service → OpenAI Responses API → validated advisory → dashboard
```

The existing public report contracts omit individual findings. This version therefore
offers only server-owned findings generated from `tests/fixtures/graph/connected.json`,
explicitly labeled SYNTHETIC and independent of uploaded dashboard reports. It does
not expose private finding IDs or expand existing sanitized reporting contracts.
Future real-plan advisory requires a separately reviewed public finding contract.

The provider receives exactly `control_id`, `domain`, `severity`, `status`, and
`resource_type`. It receives no resource identity, messages, paths, accounts, ARNs,
bucket names, IPs, risk reports, exception metadata, Terraform source/state/plans,
credentials, policy documents, graph topology or arbitrary browser metadata.
The browser submits only a bounded `finding_id` resolved against the server catalog.

## Local setup

Python 3.12 is the tested runtime. Create an isolated environment; do not install
SDK dependencies into the Checkov/security environment:

```powershell
python -m venv .tools/advisory-venv
.tools/advisory-venv/Scripts/python.exe -m pip install -r backend/requirements.lock
# Set OPENAI_API_KEY securely in this server process environment; never in Vite.
$env:OPENAI_MODEL = 'gpt-6.1-sol'
.tools/advisory-venv/Scripts/python.exe scripts/serve-advisory.py
```

In a separate terminal:

```powershell
cd frontend
npm ci
npm run dev
```

The placeholder-only `backend/.env.example` documents the two variables. No env
file is automatically loaded. Actual `.env` files remain ignored. Missing key does
not prevent startup; the selector reports “Live AI advisory is not configured.”
No paid request occurs on startup or page load. Load the synthetic selector, choose
a finding and click **Explain with AI** to consume one request. That click is the
explicit paid action. Existing offline advice remains separately labeled.

The model is centralized server-side, defaults to the requested `gpt-6.1-sol`, and
can be changed via `OPENAI_MODEL`. Account/model availability is not verified;
unsupported models return a safe provider error. There is no fallback model.
The implementation follows the official [Structured Outputs documentation](https://developers.openai.com/api/docs/guides/structured-outputs).

`requirements.txt` pins the two direct dependencies; `requirements.lock` records all
19 runtime dependency versions from the isolated installation. The SDK is not
installed into the existing security toolchain. Live proxy integration is configured
for local Vite development on port 5173; a static production host needs an explicitly
reviewed same-origin backend route before live advisory will work there.

## Boundaries and operational limits

- Official pinned Python SDK; Responses API, strict closed JSON schema, no tools,
  `store=False`, 1600 output tokens, 25-second SDK timeout, zero SDK retries.
- 256-byte HTTP body limit, fixed routes, JSON only, fixed loopback Host and
  allowlisted development Origins. No CORS, static file serving or raw prompt API.
- One in-flight provider call; duplicate requests rejected while busy; successful
  identical references cached for this process. Maximum three new attempts/minute
  and ten/hour globally, including failures. Cache has at most the fixed catalog size.
- Six advisory text fields, 1200 characters each, at most 10000 provider text bytes.
  Unexpected authority fields, malformed/refused/incomplete output, unsafe text and
  credential markers are rejected. React displays plain escaped text, never HTML.
- Provider exceptions, request headers, keys and body values are never logged or
  returned. Frontend errors are fixed messages. Keys remain in the backend process.
  SDK debug environment settings should remain disabled.
- Prompt instructions treat input as untrusted data. Browser text is never sent;
  no free-form finding messages are accepted. The model has no execution tools.
  Prose remains untrusted advice even after shape validation; human review is required.

This is a local single-user service, not an internet-facing production API. Do not
expose port 8787, the Vite proxy, or a key-bearing service publicly. Multi-user hosting
requires authentication, TLS, shared rate limits and project spend controls. Process
restart resets limits/cache. `store=False` is not a zero-retention guarantee for the
provider. Set a separate project spend budget before enabling paid use.

Tests mock OpenAI and never need a key. Python tests live in normal offline unittest
discovery, so existing offline CI runs them without SDK installation. Frontend tests
cover no automatic calls, no-key, explicit action, loading, success and safe errors.
No GitHub workflow or permissions change is required. Backend dependency audit uses
`pip-audit`; frontend uses `npm audit`. A real paid smoke test is intentionally NOT RUN.

AWS is never contacted by this service. Phase 5.2 remains paused pending account
verification. No apply, destroy, deployment, report mutation or automatic remediation
is implemented.

## Executed validation

- Full offline runner: PASS; 659 Python tests, zero skips, including 12 new mocked
  advisory tests. Separate real-loopback mocked HTTP integration: 1 PASS in both
  security and isolated backend environments. Isolated no-key startup and official
  SDK client construction: PASS without network requests.
- Frontend: production build PASS, 43 tests PASS, 3 headless Chrome checks PASS,
  8 existing exporter tests PASS, source/build privacy checks PASS.
- Terraform workload/bootstrap formatting, cached backend-free initialization and
  validation: PASS. TFLint with AWS ruleset: PASS.
- Checkov: 30 passed, 0 failed, 6 skipped, 0 parsing errors. Exact exception contract:
  expected 6, observed 6, missing 0, unexpected 0. OPA: 35 PASS; Conftest: 6 fixtures PASS.
- Destructive-command guard and reviewed local CI contract: PASS. CI contract test
  subset: 69 PASS outside the Windows sandbox; sandbox receipt rename was blocked.
- Fresh Phase 3 and Phase 4 integrations: PASS; repeated outputs byte-identical.
  Current-source Phase 3 real-plan policy remains UNKNOWN.
- npm audit and pinned backend dependency audit: zero known vulnerabilities.
  Credential scan of tracked/intended files: PASS; existing synthetic privacy-test
  canaries are identified explicitly. No actual credentials found.

One pre-existing roadmap test still expected Phase 5.1 pending after the dashboard
commit had documented the verified hosted run. It now asserts that exact run/commit,
Phase 5 remains in progress and Phase 5.2 remains blocked. No security policy or
workflow contract was weakened. The normal browser-test port was occupied; browser
checks used `CLOUDGUARD_TEST_PORT=5175` without stopping the existing server.
Paid live OpenAI/model access and hosted AI integration: NOT RUN.
