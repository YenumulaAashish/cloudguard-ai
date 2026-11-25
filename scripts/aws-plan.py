"""Explicit authenticated entry point; only reuse current passing offline evidence."""
import argparse
import subprocess
import sys
from cloudguard.evidence import begin, context, load, fingerprint, generate, record
from cloudguard.runtime import ROOT, REPORTS, PRIVATE, write_json, read_json
from cloudguard.safety import inspect
from cloudguard.scanning import security_scan
from cloudguard.policy_testing import policy_tests
from cloudguard.planning import create_plan, evaluate_plan
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
            # Revalidate quota receipt, current gates, protection and expiry after STS.
            authorized = subprocess.run([sys.executable, str(ROOT / 'scripts/planning-authorization.py'), 'start'], cwd=ROOT).returncode == 0
            deadline = read_json(PRIVATE / 'planning-reservation.json')['deadline'] if authorized else None
            ok = authorized and create_plan(deadline=deadline) and evaluate_plan()
        else:
            record("plan-summary", {"result": "FAIL", "reason": "Offline gates absent, stale or failing"})
    finally:
        generate()
    raise SystemExit(0 if ok else 1)
