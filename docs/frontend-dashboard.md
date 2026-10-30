# Frontend security dashboard

CloudGuard's dashboard is a static, offline React application. It requires no AWS
account, credentials, backend or AI API. AWS is required later for Phase 5.2 real-plan
integration, which remains **BLOCKED pending account verification**. Deployment is
disabled. The UI cannot connect AWS or make deployment decisions.

```text
Terraform / supplied offline fixture
        ↓
CloudGuard deterministic analyzers + existing report integrators
        ↓
Sanitized reports and completion receipts
        ↓
Bounded export → closed-schema adapter
        ↓
React dashboard (informational only)
```

**Deterministic tools decide. AI explains. PR reporting informs.** No JavaScript
risk engine, policy evaluator, exception approval, AWS SDK or live AI client is
introduced. All existing Terraform, schemas, Python engines and CI workflows are
unchanged.

## Run and build

Use Node **22.20.0** (`frontend/.nvmrc`) and npm **10.9.3**, the tested environment.
Direct dependencies use exact versions; `package-lock.json` pins the dependency
tree. `npm ci` is preferred for repeatable installations. Initial package downloads
need npm registry access; the installed application itself runs offline.

```sh
cd frontend
npm install
npm run dev
# Open the local URL printed by Vite (127.0.0.1:5173 by default).
npm test
npm run build
npm run preview
```

Serve **only `frontend/dist/`** for a production static site, never the repository
root. Hash routing supports static hosts without a backend or URL rewrites. No
deployment/hosting service is configured. The Vite development server binds to
loopback, restricts its filesystem to the frontend and has no public-directory
passthrough. Environment files are not loaded into the application.

Stack: React, TypeScript, [Vite](https://vite.dev/guide/),
[Tailwind CSS's Vite plugin](https://tailwindcss.com/docs/installation/using-vite),
[React Router declarative routing](https://reactrouter.com/start/declarative/routing),
Recharts, Lucide and Ajv Draft 2020-12 validation. No graph dependency is necessary:
the existing public contract supports a summary explorer, not resource topology.
Fonts and visual assets are local/system resources; no CDN is used.

## Structure

| Directory | Responsibility |
|---|---|
| `frontend/src/types/` | TypeScript interfaces for the four existing public contracts |
| `frontend/src/data/` | Reviewed aggregate-only demo snapshot and unchanged schema copies |
| `frontend/src/services/` | Bounded parser, validation, in-memory loading and aggregate adapter |
| `frontend/src/components/` | Shared UI, accessible text equivalents for charts |
| `frontend/src/pages/` | Eight dashboard pages |
| `frontend/scripts/` | Public-only export, export tests and source/build privacy checks |
| `frontend/tests/browser/` | Real Chrome layout, routing, import, network and filesystem checks |

Pages: Overview, Findings, Cloud Posture, Risk Analysis, Security Graph, AI Advisory,
CI / Scan Status and AWS Integration. Filters/search operate on actual aggregate
groups. Every displayed row is explicitly a group, never a fabricated finding.

## Exact data sources and provenance

The committed demo is a deliberately reviewed public fixture, not an automatic
publication of generated reports. The exporter reads **only** these four files:

| Contract | Demo origin at the completed Phase 5.1 checkpoint | Used for |
|---|---|---|
| `security/pr-summary.schema.json` | `reports/sanitized/phase51-final-regression/pr-summary.json` | Original Phase 3 risk, finding totals, four gate fields, advisory mode/count |
| `security/phase3-evidence.schema.json` | `reports/sanitized/phase51-final-regression/phase3-evidence.json` | Offline Phase 3 completion |
| `security/cloud-posture-summary.schema.json` | `reports/sanitized/phase51-final-smoke/posture-summary.json` | IAM/network/data severity aggregates, overall category, unresolved graph count |
| `security/phase4-completion.schema.json` | `reports/sanitized/phase51-final-smoke/phase4-completion.json` | Offline Phase 4 integration completion |

Phase 3 originated from the existing local Checkov source scan/reporting chain.
Its supplied risk is 13/LOW with review required, six approved exceptions and zero
failed findings. These values are **data**, not UI constants. Phase 4 originated
from the existing `tests/fixtures/graph/connected.json` synthetic fixture and the
unchanged analyzers. The UI labels the two scopes separately; it does not combine
their findings into a single scan total or let synthetic CRITICAL posture overwrite
the Phase 3 risk score. INFO is supported as a visual severity but no INFO findings
are invented where the source contract does not contain them.

The four schema copies are generated from the existing `security/` files; the
safety check requires deep equality. No upstream schema is modified. Receipts
must be present with their summaries and pass their existing closed schemas.
Checks include count consistency and matching advisory mode. This is not proof
of authenticity or same-plan provenance: copied or stale valid receipts remain
possible. Freshness, authenticity and same-plan context stay UNKNOWN. No timestamp
or hosted result is invented. A historical Phase 4 receipt's `phase5_status` is
not used as the current project roadmap.

Checkov/exception/test PASS values shown are **local snapshot evidence**. Real-plan
OPA/Conftest remains UNKNOWN. Hosted CI status is UNKNOWN in this bundle because
the four contracts contain no hosted run identity, even though Phase 5.1 hosted CI
has been verified separately. Normalized finding counts are not Checkov scan totals.

## Refresh or import safely

Generate fresh reports using the existing Phase 3/4 CLIs into new ignored report
directories. Review the intended evidence scope. From the repository root, with
the existing Python security toolchain installed:

```sh
python frontend/scripts/export-reports.py --phase3-dir reports/sanitized/EXPLICIT_PHASE3_RUN --phase4-dir reports/sanitized/EXPLICIT_PHASE4_RUN
```

The exporter accepts resolved paths **only below `reports/sanitized/`**, loads four
fixed filenames, rejects duplicate keys, enforces 4096 bytes per input and calls
the existing Python schema/summary validators before writing. It updates only the
fixed `frontend/src/data/demo.json` and `contracts.json` outputs. Review these changes
before committing a refreshed snapshot. It never discovers or opens private reports.
Generated runtime reports otherwise retain the repository's existing ignore rules.

The **Load sanitized bundle** button reads this same wrapper in browser memory:

```text
{ version: "1.0", source: "OFFLINE_SYNTHETIC",
  pr: <existing PR summary>, phase3: <existing Phase 3 receipt>,
  posture: <existing sanitized posture>, phase4: <existing Phase 4 receipt> }
```

A missing report pair may be `null`/`null`; a summary with no receipt is rejected.
The whole input is limited to 20,000 UTF-8 bytes. Exact keys, schema constants,
enums, primitive types, bounds and basic public consistency are validated before
React receives data. Invalid input replaces the current view with a value-free
error; it never falls back silently to PASS or retains the previous score. Reset
demo is explicit. No filename, input error detail or raw JSON is echoed.

Imported reports are untrusted user-supplied snapshots. Schema validity does not
prove that gates ran. Nothing is uploaded, stored in browser storage, or fetched
from an API. Loading a report cannot change the AWS pending status.

Later Phase 5.2 can supply the same sanitized contract bodies through a reviewed
provenance adapter without rewriting page components. **REAL AWS PLAN input is
currently rejected**: real-plan labeling and authentication evidence are not yet
implemented. Do not change `source` by hand to claim a verified scan.
An offline bundle with a known real-plan gate verdict is also rejected rather than
silently relabeled or overridden.

## Privacy and honest limitations

The public contracts exclude resources, control IDs, policies, paths, account
identifiers, hashes, raw plans, state, graph nodes/edges/associations, advisory prose
and provider metadata. These cannot be reconstructed by this frontend. Consequently:

- Findings is a searchable aggregate table with severity/domain/status filters.
  Per-finding resource/control/message/review details are unavailable.
- Risk displays the original engine result and public status counts. Per-finding
  rankings, Phase 3 severity distributions and score factors remain unavailable.
- AI Advisory displays the recorded mode/count and an informational-only label.
  Explanations/remediation text remain private; substitute advice is not generated.
- Security Graph provides an interactive domain-summary explorer and unresolved
  count. Nodes, edges and association counts are withheld, including aggregate
  graph statistics absent from the public summary. It makes no runtime claims.

Missing, malformed, empty, unavailable and UNKNOWN states are distinct. UNKNOWN
has its own purple badge, never PASS styling. Domain NONE and zero unresolved
references do not assert AWS safety. Aggregate posture may still be sensitive to
an organization; review before publicly hosting any future report.

Privacy tests enforce closed schemas, reject extra private fields/canaries, compare
schema copies to the engine, reject secrets/plan/state/topology markers in served
source/build output, prohibit outbound application transports, and verify the dev
server cannot serve repository files. This defense is data minimization plus
allowlisted contracts, not a claim that regex scanning detects every possible secret.
Build output, dependencies, test screenshots and `.env` files are ignored. No
environment secrets, remote assets or source maps are shipped.

## Validation

```sh
# frontend/
npm test
npm run build
npm run test:browser
# Repository root, existing Python toolchain:
python frontend/scripts/test_export.py -v
python scripts/run-offline.py
python scripts/verify-hosted-ci.py
```

Browser checks use installed Google Chrome in headless mode. Install Chrome
separately when unavailable; the tests do not silently skip or download a browser.
They exercise desktop/mobile/tablet layouts, all routes, filters, invalid imports,
absence of external requests, absence of page errors and the Vite filesystem
boundary. Screenshots stay in ignored `frontend/test-results/`.

Frontend validation is an explicit local command in this change. Existing reviewed
GitHub workflows and their hashes are deliberately untouched; hosted frontend
testing is NOT RUN. Phase 5.2 remains blocked, and no later phase is marked complete.

### Executed local validation for this change

| Validation | Result |
|---|---|
| npm installation / dependency audit | PASS; zero reported vulnerabilities |
| TypeScript + Vite production build | PASS |
| Vitest component/adapter tests | 40 PASS |
| Python public-export boundary tests | 8 PASS |
| Headless Chrome checks | 3 PASS; desktop/mobile/tablet screenshots inspected |
| Frontend schema/privacy checks | PASS before and after build |
| Existing Python suite | 647 PASS, zero skips |
| Terraform formatting, backend-free init, validation | PASS for workload and bootstrap |
| TFLint including AWS ruleset | PASS |
| Checkov 3.2.471 | 30 passed / 0 failed / 6 skipped / 0 parsing errors |
| Exception contract | PASS; expected 6, observed 6, missing 0, unexpected 0 |
| OPA / Conftest | 35 OPA tests and 6 Conftest fixtures PASS |
| Destructive-command guard / reviewed CI contract | PASS / PASS (local static scope) |
| Integrated offline runner | PASS |
| Fresh Phase 3 / synthetic Phase 4 integration | PASS; all four public documents match the bundled snapshot |

Terraform used the existing filesystem provider mirror with checkpoint calls
disabled. No AWS API, authentication, protected workflow, deployment, apply or
destroy was performed. Network communication for this task was limited to public
development dependency/documentation access and loopback browser testing. The
existing security configuration, six exceptions, risk model and policies were
unchanged. Hosted frontend checks remain NOT RUN.
