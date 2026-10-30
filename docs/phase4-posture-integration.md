# Phase 4 closure: deterministic posture integration

**Deterministic tools decide. AI explains. PR reporting informs.**

**Phase 4 posture does not replace Phase 3 policy or risk authority.**

This informational integrator consumes four explicit local reports. It does not
scan Terraform, rerun analyzers, construct new graph relationships, access AWS,
call AI or deploy. Phase 5 is not implemented. Phase 4 closure covers the locally
validated offline implementation and its documented uncertainty, not production
readiness, deployed security or verified same-plan provenance.

## Inputs and context model

Provide --iam-report, --network-report, --data-report and --graph-report. There
is no directory discovery, newest-file selection or implicit input. Each input is
bounded and passes its existing formal schema and runtime validator first.
Wrong producers, unsupported versions, bad counts, controls/severity/messages and
extra invalid fields fail before output publication.

Existing 4.1–4.4 reports have no plan fingerprint or run attestation. Modifying
those formats would break established byte baselines. This implementation retains
explicit same_plan=UNKNOWN, freshness=UNKNOWN and authenticity=UNKNOWN rather than
inventing evidence. No plan input/fingerprint is used and there is no VERIFIED
mode. An integration manifest pairing hashes with an arbitrary plan would not
prove those analyzers actually processed that plan, so none is fabricated.

The private report records SHA-256 for each supplied validated report's canonical
JSON: existing serialize(report), sorted object keys, indent 2, ASCII escapes,
finite numbers only and one final LF, encoded UTF-8. Array order is preserved.
These identify canonical content, not raw whitespace/BOM differences. They are
not timestamps, signatures, source trust, freshness or same-plan proof. They are
excluded from public outputs. Changed content changes its fingerprint, even when
cross-report identities still match. Same-address stale content cannot always be
detected and remains explicitly unverified. Future trusted producer-side context
binding requires a separately reviewed contract; it is not implemented here.

## Consistency and authority

The graph must contain exactly the unique node/analyzer/control/severity/status
association tuples derived from all three supplied finding sets. Missing, extra,
duplicate or mismatched associations fail. Finding resources must exist in the
graph and belong to the matching analyzer domain. Data checks must contain one
record for every supported category on every graph bucket, with no duplicates.
Duplicate unresolved graph records fail. These establish structural consistency,
not report authenticity or common-plan provenance.

Analyzer counts are verified against findings by their existing validators. Exact
or contradictory duplicate finding identities are rejected rather than silently
repaired. IAM identity uses resource/policy kind/statement index/control; network
uses resource/direction/rule index/family/control/service port; data uses
resource/category/control. Distinct valid diagnostics remain intact. The private
report copies every accepted finding field, status, severity and fixed message
unchanged; graph association tuples and unresolved records are preserved.
No control IDs are replaced. No graph path produces a new finding or severity.

IAM, network and data analyzers retain structural security authority; graph retains
relationship authority; Phase 3.2 retains risk scoring and Phase 2/3 retain gates.
Phase 3 risk 13/LOW is not overwritten by a Phase 4 category. There is no posture
score, weighting, severity averaging, risk multiplier or policy PASS inference.

## Exact posture aggregation

Each analyzer domain reports finding count, LOW/MEDIUM/HIGH/CRITICAL/UNKNOWN
severity counts, highest category, unknown-context count and requires_review.
Known category order is NONE < LOW < MEDIUM < HIGH < CRITICAL. A domain's category
is its highest known finding severity. With no known severities but UNKNOWN
findings or unknown data checks, it is UNKNOWN; with neither, it is NONE.
Unknown counts remain visible alongside a known category. Data check UNKNOWN
counts are separate context counts and are not added to finding counts.

Domain requires_review preserves any source finding's review flag and unknown
context. Graph reports counts and unresolved-driven review only, without assigning
vulnerability severity or using graph size as risk. Overall category is the
maximum known analyzer-domain category. If there is no known severity, it is
UNKNOWN when an analyzer domain is UNKNOWN, otherwise NONE. Graph unresolved
records never become vulnerability severity.

Overall requires_review is always true in this contract because report-context
verification is unavailable, even for empty finding sets. Domain/graph review flags
also expose their own local review needs. HIGH + HIGH remains HIGH, not CRITICAL.
NONE does not certify AWS secure. A successful report/receipt does not mean a policy
gate passed, an unknown became safe or infrastructure was deployed.

## Outputs, schemas and completion protocol

Default new directories:

- reports/private/phase4/integration/posture.json: bounded context fingerprints,
  domain/overall aggregates, complete accepted findings, data checks, graph
  unresolved records and finding associations. Nodes/edges and raw plans/policies
  are not duplicated.
- reports/sanitized/phase4/posture-summary.json: fixed identity, informational flag,
  phase 4, domain aggregates, unresolved graph count/review and overall posture.
- reports/sanitized/phase4/phase4-completion.json: the completion receipt.

The summary contains VALID_RECEIPT_REQUIRED, with no premature COMPLETE phase
status. Only the receipt declares Phase 4 and components 4.1–4.5 COMPLETE and
Phase 5 NOT_STARTED. This means integrated formats/components validated and the
bundle was published, not that upstream analyzers were freshly executed or their
context verified. Context remains UNKNOWN in every output.

The receipt records only actual integration checks: input schemas, cross-report
consistency, output schemas and byte reproduction. It makes no invented per-run
regression/privacy scan, source-authenticity or upstream side-effect attestation.
Repository regression/privacy evidence is documented separately in evidence.md.

Schemas cloud-posture-report, cloud-posture-summary and phase4-completion close
all objects and constrain enums/strings/counts/arrays. Private finding definitions
reuse the existing bounded source contracts. Existing jsonschema/referencing are
required; remote schema retrieval is explicitly denied. No dependencies are added.

Publication reuses Phase 3's boundary and exclusive-file helpers. Both output
directories must be new, strictly below their resolved private/sanitized roots;
even existing empty directories are collisions. The integrator deep-copies input,
validates and renders twice, compares every byte, reserves directories, writes
private/summary files, validates readback and compares bytes. It then writes and
checks a temporary receipt and renames it to phase4-completion.json LAST.

Ordinary failures remove only owned files and reserved directories; no recursive
cleanup or overwrite occurs. This is not a two-directory atomic transaction.
Hard termination, failed cleanup or power loss can leave incomplete files. A
summary without the valid final receipt is incomplete; consumers require all
validated files and successful runner completion. A malicious process controlling
the workspace or copying receipts is outside this trusted-workspace protocol.
The receipt is not a signed attestation and file fsync is not a full durability
transaction across directories.

## Privacy, bounds and CLI

Public objects are constructed from numeric counts, fixed booleans/enums and
constants. No arbitrary source text, topology, node/edge identifiers, names, role
names, CIDRs, policies, messages, paths, AWS accounts, ARNs or private hashes are
copied. No Markdown/HTML rendering or automatic publishing occurs. Public schemas
and canary tests establish data minimization; a regex is not the primary defense.
Private identities may contain sensitive Terraform instance keys; protect the
workspace and inherited Windows ACLs. Absolute path-shaped node identities fail.
Input files are read locally; strings are never shell-interpolated or executed.

Limits: four reports, 8 MiB canonical JSON per input (CLI prechecks file size),
4096 findings per analyzer, 16 MiB private output and 4096 UTF-8 bytes per public
file. Existing graph limits remain 1024 nodes and 8192 edges/unresolved/associations,
with existing per-record bounds. Data checks are at most 2048 records. Exact hash
evidence is four fixed digests. No unbounded free-form metadata is introduced.

```sh
python scripts/run-phase4.py --help
python scripts/run-phase4.py --iam-report IAM.json --network-report NETWORK.json --data-report DATA.json --graph-report GRAPH.json --private-output-dir reports/private/phase4/new-run --sanitized-output-dir reports/sanitized/phase4-new-run
```

Use a graph generated with the same three intended reports; missing claimed
associations fail. No plan parsing, analyzer execution, dependency installation,
AWS authentication or API key is required. Exit 0 means completed publication,
including unresolved/unverified posture. Exit 2 means fixed, value-free input,
schema, consistency, size or output error. Reruns require fresh output directories.

Determinism excludes timestamps, random IDs, host/Git state and filesystem order.
Byte-identical inputs reproduce all three outputs byte-for-byte. SHA-256 records
canonical input identity only. Tests cover categories/UNKNOWN, authority,
inconsistency, duplicate identities, schemas, canaries, sizes, no side effects,
completion ordering, collisions, write/rename/readback failures and reproduction.
See evidence.md for final executed counts and closure results.

Workflows and prior components are unchanged. Hosted Phase 4 integration, artifact
services, OIDC, AWS authentication, real plans, deployed security and live AI are
NOT RUN. Local Phase 4 completion does not claim those capabilities were verified.
Phase 5 requires its own scope and remains NOT STARTED.
