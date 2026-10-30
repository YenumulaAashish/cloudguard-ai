"""Bounded structural IAM analysis of supplied local Terraform plan JSON."""
import fnmatch
import json
from .findings import finding, serialize, SEVERITIES, STATUSES
from .runtime import ROOT
from .risk import read_document

POLICIES = {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}
ATTACHMENTS = {"aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment",
               "aws_iam_group_policy_attachment", "aws_iam_policy_attachment"}
PRIVILEGES = {"createpolicyversion", "setdefaultpolicyversion", "attachuserpolicy", "attachrolepolicy",
              "attachgrouppolicy", "putuserpolicy", "putrolepolicy", "putgrouppolicy", "addusertogroup",
              "createaccesskey", "updateassumerolepolicy"}
CONTROLS = {
 "CGA_IAM_001": ("CRITICAL", "Full administrator-shaped Allow; effective access requires review"),
 "CGA_IAM_002": ("HIGH", "Global wildcard Allow action"),
 "CGA_IAM_003": ("HIGH", "Service or partial wildcard Allow action"),
 "CGA_IAM_004": ("MEDIUM", "Allow uses wildcard resources; some actions require this scope"),
 "CGA_IAM_005": ("HIGH", "IAM privilege-management capability; escalation is not established"),
 "CGA_IAM_006": ("HIGH", "PassRole with wildcard resource; exploitation is not established"),
 "CGA_IAM_007": ("MEDIUM", "Resource-scoped PassRole capability"),
 "CGA_IAM_008": ("HIGH", "Trust Allow includes an unrestricted principal"),
 "CGA_IAM_009": ("MEDIUM", "Federated trust lacks a nonempty Condition; external restrictions are unknown"),
 "CGA_IAM_010": ("UNKNOWN", "Unsupported or unresolved IAM context requires review")}
MAX_BYTES = 8 * 1024 * 1024


def require(test):
    if not test:
        raise ValueError("Unsupported, malformed or oversized IAM input")


def strings(value):
    values = [value] if isinstance(value, str) else value
    require(isinstance(values, list) and 0 < len(values) <= 128)
    require(all(isinstance(s, str) and 0 < len(s) <= 2048 for s in values))
    return values


def unknown(value):
    require(value is None or isinstance(value, (bool, dict, list)))
    return value is True or (isinstance(value, dict) and any(unknown(v) for v in value.values())) or (isinstance(value, list) and any(unknown(v) for v in value))


def validate(report):
    from jsonschema import Draft202012Validator
    from referencing import Registry
    from referencing.exceptions import NoSuchResource
    def deny(uri):
        raise NoSuchResource(ref=uri)
    schema = read_document(ROOT / "security/iam-report.schema.json")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, registry=Registry(retrieve=deny)).validate(report)
    require(report["summary"] == summary(report["findings"]))
    for row in report["findings"]:
        level, message = CONTROLS[row["control_id"]]
        require(row["severity"] == level and row["message"] == message)
        require(row["status"] == ("UNKNOWN" if level == "UNKNOWN" else "FINDING"))


def summary(rows):
    return {"total": len(rows), **{s.lower(): sum(r["severity"] == s for r in rows) for s in SEVERITIES}}


def analyze(plan):
    require(isinstance(plan, dict) and plan.get("format_version") in ("1.0", "1.1", "1.2"))
    require(not plan.get("errored") and not plan.get("deferred_changes"))
    require(len(serialize(plan).encode()) <= MAX_BYTES)
    root = plan.get("planned_values", {}).get("root_module")
    require(isinstance(root, dict))
    resources = []
    modules = [0]
    def visit(module, depth=0):
        modules[0] += 1
        require(isinstance(module, dict) and depth <= 32 and modules[0] <= 4096)
        rows, children = module.get("resources", []), module.get("child_modules", [])
        require(isinstance(rows, list) and isinstance(children, list))
        resources.extend(rows); require(len(resources) <= 2048)
        for child in children: visit(child, depth+1)
    visit(root)
    changes = plan.get("resource_changes", [])
    require(isinstance(changes, list) and len(changes) <= 2048)
    by_address = {}
    for row in changes:
        require(isinstance(row, dict) and isinstance(row.get("address"), str) and isinstance(row.get("change"), dict))
        require(row["address"] not in by_address)
        by_address[row["address"]] = row
    # Changes are authoritative for after/after_unknown. Also cover unknown creates
    # omitted from planned_values and omit delete-only objects.
    indexed = {}
    for row in resources:
        require(isinstance(row, dict) and isinstance(row.get("address"), str) and isinstance(row.get("type"), str))
        require(row["address"] not in indexed)
        indexed[row["address"]] = row
    for address, row in by_address.items():
        require(isinstance(row.get("type"), str))
        if address in indexed: require(indexed[address]["type"] == row["type"])
        indexed[address] = {**row, "values": row["change"].get("after")}
    rows = []
    def emit(address, kind, index, control, conditioned=False):
        level, message = CONTROLS[control]
        rows.append({"control_id": control, "resource": address, "policy_kind": kind,
                     "statement_index": index, "status": "UNKNOWN" if level == "UNKNOWN" else "FINDING",
                     "severity": level, "conditioned": conditioned, "requires_review": True, "message": message})
        require(len(rows) <= 20000)
    def policy(address, raw, kind):
        if raw is None: emit(address, kind, None, "CGA_IAM_010"); return
        if isinstance(raw, str):
            require(len(raw.encode()) <= 262144)
            def unique(pairs):
                obj = {}
                for k,v in pairs: require(k not in obj); obj[k] = v
                return obj
            raw = json.loads(raw, object_pairs_hook=unique)
        require(isinstance(raw, dict) and len(serialize(raw).encode()) <= 262144)
        statements = raw.get("Statement")
        if statements is None: emit(address, kind, None, "CGA_IAM_010"); return
        if isinstance(statements, dict): statements = [statements]
        require(isinstance(statements, list) and len(statements) <= 256)
        seen = set()
        for i, s in enumerate(statements):
            require(isinstance(s, dict))
            identity = serialize(s)
            if identity in seen: continue
            seen.add(identity)
            conditioned = bool(s.get("Condition"))
            if "Condition" in s: require(isinstance(s["Condition"], dict))
            if s.get("Effect") == "Deny": continue
            if s.get("Effect") != "Allow" or any(k in s for k in ("NotAction", "NotResource", "NotPrincipal")):
                emit(address, kind, i, "CGA_IAM_010", conditioned); continue
            if "Action" not in s:
                emit(address, kind, i, "CGA_IAM_010", conditioned); continue
            actions = [x.lower() for x in strings(s["Action"])]
            if kind == "trust":
                if not all(a in ("sts:assumerole", "sts:assumerolewithwebidentity", "sts:assumerolewithsaml") for a in actions):
                    emit(address, kind, i, "CGA_IAM_010", conditioned); continue
                principal = s.get("Principal")
                if principal is None:
                    emit(address, kind, i, "CGA_IAM_010", conditioned); continue
                require(isinstance(principal, (dict, str)))
                public = principal == "*"
                if isinstance(principal, dict):
                    require(0 < len(principal) <= 8)
                    for key, value in principal.items():
                        vals = strings(value)
                        public |= "*" in vals
                        if key not in ("AWS", "Service", "Federated", "CanonicalUser"):
                            emit(address, kind, i, "CGA_IAM_010", conditioned)
                    if "Federated" in principal and not conditioned:
                        emit(address, kind, i, "CGA_IAM_009")
                elif principal != "*": emit(address, kind, i, "CGA_IAM_010", conditioned)
                if public: emit(address, kind, i, "CGA_IAM_008", conditioned)
                continue
            if "Resource" not in s:
                emit(address, kind, i, "CGA_IAM_010", conditioned); continue
            scope = strings(s["Resource"])
            broad = any("*" in x or "?" in x for x in scope)
            if "*" in actions and "*" in scope:
                emit(address, kind, i, "CGA_IAM_001", conditioned); continue
            if "*" in actions: emit(address, kind, i, "CGA_IAM_002", conditioned)
            elif any("*" in a or "?" in a for a in actions): emit(address, kind, i, "CGA_IAM_003", conditioned)
            if broad: emit(address, kind, i, "CGA_IAM_004", conditioned)
            if any(fnmatch.fnmatchcase("iam:"+a, pattern) for a in PRIVILEGES for pattern in actions):
                emit(address, kind, i, "CGA_IAM_005", conditioned)
            if any(fnmatch.fnmatchcase("iam:passrole", a) for a in actions):
                emit(address, kind, i, "CGA_IAM_006" if broad else "CGA_IAM_007", conditioned)
    for address, row in sorted(indexed.items()):
        typ = row["type"]
        if not typ.startswith("aws_iam_"): continue
        require(0 < len(address) <= 2048)
        change = by_address.get(address, {}).get("change", {})
        if change.get("actions") == ["delete"]: continue
        values = row.get("values")
        if unknown(change.get("after_unknown", {})):
            # A known policy can still be inspected when unrelated attributes are unknown.
            mask = change.get("after_unknown")
            field = "assume_role_policy" if typ == "aws_iam_role" else "json" if typ == "aws_iam_policy_document" else "policy"
            if mask is True or (isinstance(mask, dict) and unknown(mask.get(field))):
                emit(address, "trust" if typ == "aws_iam_role" else "permissions", None, "CGA_IAM_010"); continue
        if typ in POLICIES or typ == "aws_iam_role":
            kind = "trust" if typ == "aws_iam_role" else "permissions"
            require(values is None or isinstance(values, dict))
            policy(address, (values or {}).get("assume_role_policy" if kind == "trust" else "policy"), kind)
            if typ == "aws_iam_role" and ((values and (values.get("inline_policy") or values.get("managed_policy_arns"))) or
                    (isinstance(change.get("after_unknown"), dict) and any(unknown(change["after_unknown"].get(k)) for k in ("inline_policy", "managed_policy_arns")))):
                emit(address, "permissions", None, "CGA_IAM_010")
        else:
            # Attachments, policy-document data sources and other IAM resources are
            # explicitly unresolved. Never fetch policies or infer relationships.
            emit(address, "permissions", None, "CGA_IAM_010")
    rows.sort(key=lambda r: (r["resource"], r["policy_kind"], -1 if r["statement_index"] is None else r["statement_index"], r["control_id"]))
    report = {"schema_version": "1.0", "analyzer": "cloudguard-iam", "analysis_scope": "structural_only",
              "findings": rows, "summary": summary(rows)}
    validate(report)
    return report


def normalized(report):
    """Explicit Conftest-compatible transport, not a claim Conftest executed."""
    validate(report)
    rows = [finding("conftest", r["control_id"], r["resource"],
                    "warning" if r["status"] == "UNKNOWN" else "failed", r["severity"], r["message"],
                    metadata={"analyzer": "cloudguard-iam", "policy_kind": r["policy_kind"],
                              "statement_index": r["statement_index"], "conditioned": r["conditioned"]})
            for r in report["findings"]]
    return {"schema_version": "1.0", "generated_by": "cloudguard-ai", "sources": ["conftest"],
            "findings": rows, "summary": {"total": len(rows),
            **{s.lower(): sum(r["severity"] == s for r in rows) for s in SEVERITIES},
            **{s: sum(r["status"] == s for r in rows) for s in STATUSES}}}
