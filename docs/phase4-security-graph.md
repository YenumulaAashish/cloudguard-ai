# Phase 4.4: deterministic cross-resource security graph

**Deterministic tools decide. AI explains. PR reporting informs.**

**A graph relationship is not proof of exploitability or runtime reachability.**

This private configuration graph uses supplied local Terraform plan JSON. It is
not deployed topology or an attack-path engine. It never executes Terraform,
HCL interpolation, network/AWS calls or AI. Phase 4.5 is not implemented.

## Architecture and repository topology

The repository has a VPC, two subnets, standalone/default security groups, Internet
Gateway, route tables, a standalone route and associations. S3 has separate
PAB/encryption/versioning/ownership/policy/lifecycle resources. The separate
bootstrap contains an IAM role and inline policy. There is no compute, instance
profile, load balancer or database in the actual workload; fixtures demonstrate
supported compute/IAM relationships without implying deployment.

The builder reuses plan_input.project unchanged and never reruns analyzer logic.
Accepted formats are 1.0/1.1/1.2 with nested planned_values.root_module and optional
resource_changes. change.after overrides snapshots; unknown creates absent from
the snapshot remain nodes. Delete-only nodes are omitted; replacements appear
once. Errored/deferred plans, duplicate addresses and malformed envelopes fail.
Only managed mode (or omitted mode in fixtures) is included; data sources are not
managed nodes. Configuration/expression reference metadata is deliberately ignored:
count/module/conditional semantics cannot be safely inferred by string matching.
Unknown values never fall back to guessed expression edges.

## Supported nodes and typed edges

Node ID is the supplied Terraform address, with fixed PLANNED/AFTER_STATE
provenance. Categories are IAM, NETWORK, COMPUTE and STORAGE. IDs are private,
bounded and never randomly generated. Absolute path-shaped IDs are rejected.

Supported network nodes: aws_vpc, aws_subnet, aws_security_group,
aws_default_security_group, aws_security_group_rule,
aws_vpc_security_group_ingress_rule, aws_vpc_security_group_egress_rule,
aws_route_table, aws_route, aws_route_table_association, aws_internet_gateway,
aws_nat_gateway and aws_network_interface. Compute/context nodes: aws_instance,
aws_lb and aws_alb. Database nodes are not supported; other types are ignored.

Supported IAM nodes: aws_iam_role, aws_iam_user, aws_iam_group, aws_iam_policy,
aws_iam_instance_profile; role/user/group inline policies and their individual
policy-attachment resources. Global aws_iam_policy_attachment and policy-document
data sources are not supported. No external managed-policy node/content is fetched.

Supported S3 nodes: aws_s3_bucket plus separate public_access_block, acl, policy,
server_side_encryption_configuration, versioning, logging,
lifecycle_configuration and ownership_controls companions. This models ownership
relationships only; 4.3 security semantics remain unchanged.

| Relationship | Supported source evidence and direction |
|---|---|
| MEMBER_OF_VPC | subnet/SG/default SG/route table/IGW vpc_id -> VPC id |
| MEMBER_OF_SUBNET | instance/ENI/NAT subnet_id or LB/ALB subnets -> subnet id |
| USES_SECURITY_GROUP | instance vpc_security_group_ids, ENI/LB/ALB security_groups -> SG id; instance security_groups -> SG name |
| USES_INSTANCE_PROFILE | instance iam_instance_profile -> profile name |
| PROFILE_HAS_ROLE | profile role -> role name/id |
| HAS_INLINE_POLICY | principal name/id <- role/user/group inline policy field; edge principal -> inline policy |
| HAS_POLICY_ATTACHMENT | principal name/id <- attachment role/user/group; edge principal -> attachment |
| REFERENCES_POLICY | attachment policy_arn -> local managed policy arn |
| HAS_ROUTE | route table id <- route route_table_id; edge table -> route |
| ROUTE_USES_GATEWAY | route gateway_id -> IGW id or nat_gateway_id -> NAT id |
| ASSOCIATED_SUBNET / ASSOCIATED_ROUTE_TABLE / ASSOCIATED_GATEWAY | association subnet_id / route_table_id / gateway_id -> matching local node id |
| RULE_OF_SECURITY_GROUP | standalone rule security_group_id -> parent SG id |
| REFERENCES_SECURITY_GROUP | standalone source_security_group_id or referenced_security_group_id -> SG id |
| INGRESS_REFERENCES_SECURITY_GROUP / EGRESS_REFERENCES_SECURITY_GROUP | explicit inline rule security_groups identifiers -> SG id |
| BUCKET_HAS_PAB / ACL / POLICY / ENCRYPTION / VERSIONING / LOGGING / LIFECYCLE / OWNERSHIP | companion bucket -> local bucket bucket/id; edge bucket -> companion |

Standalone SG rules are child nodes. Inline rules are not nodes: only explicit SG
reference lists yield group-to-group edges. Inline self=true is not expanded;
explicit own-ID references can form self-loops. Inline CIDRs, ports, public IPs,
route destinations, services and security findings do not create extra edges.
Route-table inline routes, implicit/default subnet routing, LB subnet_mapping,
ENI attachment blocks and unsupported gateway variants are not interpreted.

## Certainty, identity, provenance and unresolved references

Every ordinary edge is PROVEN under the narrow EXACT_KNOWN_VALUE contract: a
supported reference equals a known allowed identity field on exactly one supported
after-state target. Matching is type/field-specific, exact and case-sensitive.
There is no substring, suffix, naming-convention or Terraform-expression matching.
IDs, names and bucket aliases are used only for their documented reference types.
A value found in multiple candidate nodes creates AMBIGUOUS_MATCH, never a choice.
Multiple matching identity fields on the same node are not ambiguous.

Provenance records fixed source_field, target_field and direction-reversal flags;
it excludes raw identity values and source expressions. Reversed edges retain
which companion field established the relationship. Multiple proofs merge into
one source/relationship/target edge. Different relationship types remain distinct.

Unknown reference fields and whole unknown resources produce UNKNOWN_VALUE
records. Unknown target identities are excluded from matching. Missing required
or explicitly null reference values produce MISSING_VALUE. Unmatched/external or
deleted targets produce NO_LOCAL_MATCH. Optional omitted fields and known empty
reference lists produce no edge. None of these imply absence or safety in AWS.
Unresolved records contain source, relationship, source field, reason and UNKNOWN
certainty, never a fake target node. Repeated identical unresolved reasons collapse;
raw unresolved values are not exported.

For inline SG references, any unknown direction content conservatively withholds
its reference edges. Known CIDR-only rules produce no SG-reference edge. No SG
publicness or recursive exposure propagation is inferred. Cycles/self-loops are
stored as facts: the builder uses bounded lookups and sets, without DFS, path
enumeration, topological assumptions or recursive graph traversal.

## Existing finding associations and authority

Optional --iam-report, --network-report and --data-report inputs are validated
using existing schemas/runtime validators. Wrong producer/version/schema or an
unmatched/out-of-domain finding identity fails. Data check identities must also
map to supported bucket nodes. Existing analyzers are not rerun, and findings are
not rewritten. Associations retain node, analyzer, control ID, severity and status;
identical tuples collapse without creating derived severity or a new control.

This proves exact address association only. These existing reports contain no
plan attestation: callers must supply trusted reports from the intended input.
An address can be reused in another plan, so the graph does not prove freshness,
authenticity or matching policy bodies. An empty report does not prove a scan ran.
No cross-resource exploitation or automatic propagation is asserted.

There are no CGA_GRAPH findings, path correlations, risk multipliers, aggregate
posture decisions or graph-to-Phase-3 adapter. Ordinary graph facts are not security
findings. Existing Phase 3 and prior analyzer outputs remain unchanged. A later
explicitly scoped phase may define verified correlations and posture reporting.

## Bounds, privacy, schema and CLI

Shared limits: 8 MiB serialized plan, depth 32, 4096 module nodes, 2048 snapshot
resources plus 2048 changes. Graph limits: 1024 supported nodes; 8192 edges,
unresolved records and association tuples each; 128 references per source field;
256 inline rules per direction with at most 128 combined references; 2048-character
addresses/identity strings; at most 32 bounded proofs per edge. Optional reports
are each <=8 MiB and must satisfy their existing schemas. Exceeding limits fails.
There is no generalized path traversal or arbitrary metadata container.

Nodes sort by address, edges by source/relationship/target, proofs lexically by
field/key/reversal, unresolved records by source/relationship/field/reason and
associations by node/analyzer/control/severity/status. Inputs are never mutated.
There are no timestamps, random IDs, new fingerprints or environment-dependent
security classifications. Reordered equivalent resource/reference inputs reproduce
byte-identical output.

security/security-graph.schema.json closes all objects and uses bounded arrays,
strings, counts and enums. Runtime validation checks summary counts, endpoints,
categories, duplicate edges and typed provenance. Existing jsonschema/referencing
are required and remote schema retrieval is denied. No dependencies/graph library
or workflow changes are added.

```sh
python scripts/build-security-graph.py --help
python scripts/build-security-graph.py --plan tests/fixtures/graph/connected.json --output reports/private/phase4/security-graph.json
# Optional trusted local analyzer reports:
# --iam-report PATH --network-report PATH --data-report PATH
```

Reports stay strictly under reports/private and are not uploaded or published to
PRs. They include topology and Terraform addresses, which can contain sensitive
instance keys. Protect the workspace and Windows inherited ACLs. Raw plans, policy
bodies, names/ARN/ID values, condition prose, source files and absolute paths are
not copied. Messages are fixed and malicious strings remain inert data.
Exclusive creation prevents overwrite. Ordinary write failures remove owned files;
a hard kill can leave a partial file, so validate before consuming. Exit 0 means
completed graph generation, even with unresolved records. Exit 2 means fixed,
value-free input/schema/dependency/output failure.

Synthetic fixtures/tests cover topology, all relationship specifications, exact
matching/ambiguity, unknowns, deletion/replacement, provenance, cycles, bounds,
schemas, inert data, no network/execution, collisions and finding authority.
See evidence.md for actual validation. AWS runtime state, IAM effective permissions,
Internet reachability, exploitability and hosted behavior remain unverified.
Phase 4.5 remains a separate task and is not implemented here.
