"""Check executable repository locations without scanning documentation."""
from cloudguard.runtime import ROOT, REPORTS, write_json
from cloudguard.safety import inspect
from cloudguard.evidence import record

if __name__ == "__main__":
    errors = inspect(ROOT)
    result = {"result": "FAIL" if errors else "PASS", "errors": errors}
    record("ci-safety", result)
    print(f"CI deployment guard: {result['result']}")
    for error in errors:
        print(error)
    raise SystemExit(bool(errors))
