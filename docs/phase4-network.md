# Phase 4.2: deterministic network exposure

**Deterministic tools decide. AI explains. PR reporting informs.**

This offline analyzer examines supplied local Terraform plan JSON. It identifies
rule-level configuration exposure, never proves Internet reachability. It does
not execute Terraform, AWS, shell commands, network requests or AI. Phases 4.3,
4.4 and 4.5 remain outside scope.

## Architecture and supported input

The repository has an inline aws_security_group, a default-deny default group,
VPC, subnets, route tables, Internet Gateway and associations. There are no EC2,
load balancer, RDS, ElastiCache or ENI resources and no standalone SG rules today.
The analyzer nevertheless tests inline, legacy and modern standalone forms.

Supported rule sources: aws_security_group and aws_default_security_group inline
ingress/egress, aws_security_group_rule, aws_vpc_security_group_ingress_rule and
aws_vpc_security_group_egress_rule. Every form feeds the same rule evaluator.

aws_instance, aws_lb, aws_alb, aws_db_instance, aws_rds_cluster,
aws_elasticache_cluster, aws_elasticache_replication_group and aws_network_interface
produce explicit UNKNOWN context. They are not associated with rules or inspected
for reachability. Unsupported aws_security_group* types also produce UNKNOWN.
Other resources (including routes/subnets and IAM) are outside this component's
scope and ignored. No graph or route traversal is built.

A minimal shared plan_input.project helper extracts the existing IAM final-state
projection without changing its semantics or controls. Both analyzers accept
format_version 1.0/1.1/1.2 and planned_values.root_module with nested child_modules.
resource_changes.change.after overrides snapshots and adds omitted unknown creates.
Delete-only resources are omitted; replacements analyze after once. Duplicate
addresses and malformed envelopes are rejected. Errored/deferred plans fail.
The helper preserves the original IAM value-free error; the network CLI reports
its own fixed diagnostic. The network analyzer also reuses IAM's pure unknown-mask
walker. IAM detection, severity, schemas and adapters are unchanged.

## Stable controls

| ID | Rule-level condition | Severity |
|---|---|---|
| CGA_NET_001 | Public all-protocol ingress | CRITICAL |
| CGA_NET_002 | Public TCP range includes 22 | HIGH |
| CGA_NET_003 | Public TCP range includes 3389 | HIGH |
| CGA_NET_004 | Public TCP range includes a listed database port | HIGH |
| CGA_NET_005 | Public TCP range includes a listed management port | MEDIUM |
| CGA_NET_006 | Public TCP/UDP range contains at least 1024 ports | HIGH |
| CGA_NET_007 | Public ICMP/ICMPv6 ingress | LOW |
| CGA_NET_008 | All-protocol public-destination egress | LOW |
| CGA_NET_009 | Unresolved or unsupported network context | UNKNOWN |

Database TCP ports: 1433, 1521, 3306, 5432, 6379, 27017. Management TCP ports:
23, 5900, 5985, 5986. These labels describe conventional port exposure, not a
running database or service. Narrow public application ports outside these lists
are not findings. Broad ranges use inclusive width to_port - from_port + 1 >=1024.

Only exact all-address IPv4/IPv6 networks (0.0.0.0/0 and ::/0) count as public-all.
Python ipaddress validates CIDRs strictly, including version; malformed CIDRs,
host bits and address-only strings fail. Scoped private/public CIDRs never become
public-all. Equivalent IPv6 spelling is canonicalized by ipaddress. Multiple or
duplicate CIDRs do not hide or duplicate an exposure within a family. IPv4 and
IPv6 produce distinct family findings.

Protocols: tcp/6, udp/17, icmp/1, icmpv6/58 and -1/all (string or integer number).
TCP/UDP ports must be integers 0..65535 in ascending order. Missing ports become
UNKNOWN. ICMP uses type/code -1..255, not service ports; type -1 requires code -1.
Missing ICMP values become UNKNOWN. Protocol/family mismatch becomes UNKNOWN.
All-protocol semantics ignore port fields; they may be absent. Unsupported
protocols become UNKNOWN and invalid scalar types fail. UDP 22 is not SSH.

All-protocol ingress suppresses service/range controls for that rule/family.
A broad range suppresses narrower SSH/RDP/database/management controls. Otherwise
one finding per applicable control/service port/family is emitted. A narrow range
can include both SSH and Telnet. Identical public CIDRs collapse; distinct rule
indexes and distinct resource representations remain distinct. No speculative
cross-resource deduplication or relationship inference is performed.

Egress never receives ingress controls. Only unrestricted all-protocol egress is
reported, at LOW; other known egress is intentionally omitted to limit noise.
This does not establish safe outbound behavior.

Known source SG references and self=true are scoped selectors, not public CIDRs.
They are not recursively resolved. Prefix-list selectors produce UNKNOWN because
contents are unavailable; no AWS lookup occurs. A known public CIDR can still
produce a finding alongside unresolved prefix-list context. Missing selectors
produce UNKNOWN. Target SG membership/attachment and public-IP context are not
resolved. Unknown target/source SG values also require review.

## Unknowns, determinism and privacy

Relevant after_unknown fields never become safe or definitely exposed. A wholly
unknown resource emits UNKNOWN; an unknown inline direction emits UNKNOWN for
that direction. Unknown standalone CIDR, protocol, port, selector, direction or
SG identity emits UNKNOWN. This conservative policy can withhold a known partial
exposure until the whole rule is available. Unrelated computed fields do not erase
known rule evidence. Missing inline rule lists are UNKNOWN; explicit empty lists
are analyzed as empty. Invalid known types/ranges fail rather than pass.

Findings sort by resource, direction, zero-based rule index, family, control and
service port. Standalone rules use index 0; direction-wide uncertainty uses null.
No timestamp, random ID or new hash is generated. Input objects are not mutated.
Private reports contain fixed messages and selected rule scalars plus the supplied
resource identity. Descriptions, CIDR values, SG names, source code, plans, keys
and arbitrary metadata are not copied. Resource strings remain untrusted data;
no executable Markdown is produced. Nothing is uploaded or added to sanitized CI.

Bounds: 8 MiB serialized plan (CLI checks file size before parsing), 2048 snapshot
resources plus 2048 changes, 4096 module nodes and depth 32. At most 256 inline
rules per direction, 4096 evaluated rules overall, 128 entries per selector list,
2048 characters per selector/resource/description, and 20000 findings. Findings
and summaries have a closed bounded schema. Exceeded limits fail. Unknown groups
and unsupported-context resources also remain bounded by resource/finding limits.

## CLI, schema and Phase 3 compatibility

```sh
python scripts/analyze-network.py --help
python scripts/analyze-network.py --plan tests/fixtures/network/public-ssh.json --output reports/private/phase4/network-report.json
```

Output must resolve inside reports/private, with restrictive creation permissions
subject to Windows ACL inheritance. Existing files are never overwritten.
Exit 0 means completed analysis, including findings/UNKNOWN; exit 2 means input,
schema, dependency or output failure. Ordinary failed writes remove owned files.
Hard termination can leave a partial file; validate before consumption.

security/network-report.schema.json closes objects, bounds arrays/strings/numbers
and fixes IDs/enums. Runtime validation additionally binds IDs to severity,
message/status and checks summary counts. Existing jsonschema/referencing handle
validation with remote schema retrieval denied. No dependency is added.

network.normalized(report) follows the Phase 4.1 adapter: Conftest-compatible
transport, explicit cloudguard-network private metadata, failed structural findings,
warning UNKNOWNs, exception=false and null source file/lines. It does not claim
Conftest ran. Existing normalized schemas and risk defaults apply unchanged.
Production Phase 3 execution and authoritative gate binding are not modified.

Tests cover safe/public IPv4/IPv6, ports/ranges/protocols, direction, all supported
rule forms, selectors, unknowns, delete/replacement, duplicate suppression, bounds,
inert injection strings, no network/execution, collisions, schemas and Phase 3
compatibility. IAM tests and byte reproduction guard the small shared extraction.
See evidence.md for actual executed validation results.

A group rule alone does not prove public IP, Internet Gateway routing, reachable
ENI or listening service. AWS state, hosted behavior and real reachability remain
unverified. Phase 4.3 storage and 4.4 graph work require separate scope.
