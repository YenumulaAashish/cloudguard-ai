"""Execute preserved fixture tests and unit tests; process errors are not detections."""
import json
from .runtime import ROOT, tool, run
from .evidence import record, policy_summary

EXPECTED = {"public-ssh": "SSH:", "public-s3": "S3_PUBLIC:", "missing-encryption": "S3_ENCRYPTION:", "missing-tags": "TAGS:", "wildcard-iam": "IAM:"}

def fixtures():
    outcomes = []
    for path in sorted((ROOT / "tests/fixtures/secure").glob("*.json")):
        result = run(tool("conftest") + ["test", str(path), "--policy", "policies/terraform", "--output", "json"], capture_output=True)
        summary = policy_summary(json.loads(result.stdout), result.returncode)
        outcomes.append({"fixture": path.name, "expected": "PASS", "result": summary["result"]})
    for name, prefix in EXPECTED.items():
        result = run(tool("conftest") + ["test", f"tests/fixtures/insecure/{name}.json", "--policy", "policies/terraform", "--output", "json"], capture_output=True)
        rows = json.loads(result.stdout)
        failures = [f["msg"] for row in rows for f in row.get("failures", [])]
        valid = result.returncode == 1 and bool(failures) and all(msg.startswith(prefix) for msg in failures)
        outcomes.append({"fixture": name + ".json", "expected": "REJECT", "result": "PASS" if valid else "FAIL"})
    return outcomes

def policy_tests():
    evidence = {"result": "FAIL", "opa": {"result": "NOT RUN"}, "fixtures": {"result": "NOT RUN"}}
    try:
        result = run(tool("opa") + ["test", "policies", "--format", "json"], capture_output=True)
        tests = json.loads(result.stdout)
        passed = sum(not t.get("fail") and not t.get("error") and not t.get("skip") for t in tests)
        evidence["opa"] = {"result": "PASS" if result.returncode == 0 and tests and passed == len(tests) else "FAIL", "passed": passed, "total": len(tests)}
        results = fixtures()
        evidence["fixtures"] = {"result": "PASS" if results and all(r["result"] == "PASS" for r in results) else "FAIL", "cases": results}
        evidence["result"] = "PASS" if evidence["opa"]["result"] == evidence["fixtures"]["result"] == "PASS" else "FAIL"
    except (OSError, ValueError, KeyError, TypeError):
        evidence["reason"] = "Tool unavailable or invalid structured policy output"
    record("policy-tests", evidence)
    print(f"Policy tests: {evidence['result']}")
    return evidence["result"] == "PASS"
