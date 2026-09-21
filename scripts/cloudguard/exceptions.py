"""Verify the reviewed six-pair contract against source AND complete scan records."""
from collections import Counter
from .runtime import read_json
from .source import annotations
from .safety import inspect

# Deliberate security invariant: changing the JSON alone cannot expand acceptance.
REVIEWED = {
    ("CKV2_AWS_11", "module.network.aws_vpc.this"),
    ("CKV2_AWS_5", "module.security.aws_security_group.this"),
    *{(rule, "module.storage.aws_s3_bucket.this") for rule in
      ("CKV_AWS_145", "CKV_AWS_18", "CKV_AWS_144", "CKV2_AWS_62")},
}

def pairs(items):
    return [{"rule_id": rule, "resource": resource} for rule, resource in sorted(items)]

def terraform_report(raw):
    reports = raw if isinstance(raw, list) else [raw]
    matches = [r for r in reports if isinstance(r, dict) and r.get("check_type") == "terraform"]
    if len(matches) != 1:
        raise ValueError("Expected exactly one source Terraform report")
    return matches[0]

def verify(root, raw):
    errors = []
    expected = REVIEWED
    source, observed = Counter(), Counter()
    global_errors = inspect(root, suppression=True)
    errors.extend(global_errors)
    try:
        contract = read_json(root / "security/checkov-exceptions.json")
        entries = contract["exceptions"]
        declared = [(e["rule_id"], e["resource"]) for e in entries]
        if contract["schema_version"] != 1 or set(declared) != REVIEWED or len(declared) != len(REVIEWED):
            errors.append("Allowlist differs from the reviewed six-pair contract")
        if any(not e.get("rationale", "").strip() or not e.get("review_trigger", "").strip() for e in entries):
            errors.append("Missing exception rationale or review trigger")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        errors.append(f"Invalid allowlist: {type(exc).__name__}")
    try:
        source = annotations(root)
        if set(source) != expected or any(n != 1 for n in source.values()):
            errors.append("Source annotations differ from the reviewed exception contract")
    except (OSError, ValueError, IndexError) as exc:
        errors.append(f"Source inspection failed: {exc}")
    try:
        report = terraform_report(raw)
        results, summary = report["results"], report["summary"]
        for group, status, key in (("passed_checks", "PASSED", "passed"), ("failed_checks", "FAILED", "failed"), ("skipped_checks", "SKIPPED", "skipped")):
            records = results[group]  # Quiet/truncated reports must fail closed.
            if not isinstance(records, list) or summary[key] != len(records):
                errors.append(f"Invalid {group} count")
            for record in records:
                pair = (record["check_id"], record["resource"])
                if record["check_result"]["result"] != status:
                    errors.append("Inconsistent Checkov record status")
                if group == "skipped_checks":
                    observed[pair] += 1
                elif pair in expected:
                    errors.append("Accepted exception was not reported as SKIPPED")
        if results["failed_checks"]:
            errors.append("Checkov reported failed security checks")
        if summary["parsing_errors"] != 0 or results.get("parsing_errors"):
            errors.append("Checkov reported Terraform parsing errors")
        if summary.get("resource_count", 0) <= 0 or summary["passed"] <= 0:
            errors.append("Empty or non-executed scan")
        if any(n != 1 for n in observed.values()):
            errors.append("Duplicate skipped records")
        if set(observed) != expected:
            errors.append("Observed skips differ from the reviewed exception contract")
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        errors.append(f"Invalid/incomplete Checkov report: {type(exc).__name__}")
    return {
        "result": "FAIL" if errors else "PASS",
        "expected_exceptions": len(expected), "observed_exceptions": sum(observed.values()),
        "source_exceptions": sum(source.values()),
        "unexpected": pairs((set(observed) | set(source)) - expected),
        "missing": pairs((expected - set(observed)) | (expected - set(source))),
        "global_suppression_detected": bool(global_errors), "errors": errors,
    }
