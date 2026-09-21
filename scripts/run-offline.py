"""All non-deploying checks, with reports retained on failure."""
from cloudguard.runtime import ROOT
from cloudguard.evidence import begin, record, generate
from cloudguard.quality import quality
from cloudguard.safety import inspect
from cloudguard.scanning import security_scan
from cloudguard.policy_testing import policy_tests

if __name__ == "__main__":
    begin("offline")
    results = []
    try:
        errors = inspect(ROOT)
        record("ci-safety", {"result": "FAIL" if errors else "PASS", "errors": errors})
        results.append(not errors)
        for operation in (quality, security_scan, policy_tests):
            try:
                results.append(operation())
            except (OSError, ValueError) as exc:
                print(f"FAIL: {operation.__name__}: {type(exc).__name__}")
                results.append(False)
    finally:
        generate()
    raise SystemExit(0 if results and all(results) else 1)
