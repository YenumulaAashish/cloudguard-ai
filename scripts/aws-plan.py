"""Explicit authenticated entry point; only reuse current passing offline evidence."""
import argparse
from cloudguard.evidence import begin, context, load, fingerprint, generate, record
from cloudguard.runtime import ROOT, REPORTS, write_json
from cloudguard.safety import inspect
from cloudguard.scanning import security_scan
from cloudguard.policy_testing import policy_tests
from cloudguard.planning import create_plan, plan_policy
from cloudguard.quality import quality

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reuse-offline", action="store_true")
    args = parser.parse_args()
    ok = False
    try:
        if args.reuse_offline:
            ctx = context()
            required = ("checks", "checkov", "checkov-exceptions", "policy-tests", "ci-safety")
            ready = ctx["source_digest"] == fingerprint() and all(load(n).get("result") == "PASS" for n in required)
            ctx["scope"] = "authenticated-plan"
            write_json(REPORTS / "run-context.json", ctx)
        else:
            begin("authenticated-plan")
            errors = inspect(ROOT)
            record("ci-safety", {"result": "FAIL" if errors else "PASS", "errors": errors})
            ready = not errors and quality() and security_scan() and policy_tests()
        if ready:
            ok = create_plan() and plan_policy()
        else:
            record("plan-summary", {"result": "FAIL", "reason": "Offline gates absent, stale or failing"})
    finally:
        generate()
    raise SystemExit(0 if ok else 1)
