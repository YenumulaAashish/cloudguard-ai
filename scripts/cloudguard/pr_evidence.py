"""Read existing local gate records without running gates or changing evidence."""
from .evidence import fingerprint, policy_summary
from .findings import build_report, serialize
from .risk import read_document
from .runtime import REPORTS, PRIVATE
from .pr_reporting import GATES


def current_policy(normalized, directory=REPORTS, private=PRIVATE):
    """Fail closed to UNKNOWN on absent/stale/malformed/unrelated evidence.

    The workspace and gate producers must be trusted. Fingerprints bind source,
    not authenticity; this is not a signed attestation or artifact publisher.
    """
    statuses = {key: "UNKNOWN" for key in GATES}
    try:
        ctx = read_document(directory / "run-context.json")
        digest = fingerprint()
        if (not isinstance(ctx, dict) or ctx.get("source_digest") != digest
                or not isinstance(ctx.get("run_id"), str) or not ctx["run_id"]):
            return statuses
    except (ValueError, OSError):
        return statuses

    def record(name):
        try:
            value = read_document(directory / (name + ".json"))
            if (isinstance(value, dict) and value.get("run_id") == ctx["run_id"]
                    and value.get("source_digest") == digest and value.get("result") in ("PASS", "FAIL")):
                return value
        except (ValueError, OSError):
            pass
        return {}

    def matches(source, filename):
        if source not in normalized["sources"]:
            return None
        raw = read_document(private / filename)
        rows = build_report([(source, raw)])["findings"]
        supplied = [f for f in normalized["findings"] if f["source"] == source]
        if serialize(sorted(rows, key=serialize)) != serialize(sorted(supplied, key=serialize)):
            return None
        return raw

    # Real gate status is copied, never inferred from risk or zero findings.
    try:
        if matches("checkov", "checkov-raw.json") is not None:
            for key, name in (("checkov", "checkov"), ("exception_contract", "checkov-exceptions")):
                statuses[key] = record(name).get("result", "UNKNOWN")
    except (ValueError, KeyError, TypeError, OSError):
        pass
    try:
        raw = matches("conftest", "plan-policy-raw.json")
        result = record("plan-policy")
        if raw is not None and result and type(result.get("exit_code")) is int:
            expected = policy_summary(raw, result["exit_code"])
            if all(type(result.get(k)) is type(v) and result[k] == v for k, v in expected.items()):
                statuses["opa_conftest"] = result["result"]
    except (ValueError, KeyError, TypeError, OSError):
        pass
    statuses["policy_tests"] = record("policy-tests").get("result", "UNKNOWN")
    return statuses
