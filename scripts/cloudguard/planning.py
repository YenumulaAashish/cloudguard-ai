"""Authenticated planning only. Never execute deployment operations."""
import os
from .runtime import ROOT, PRIVATE, tool, run, read_json
from .evidence import record, plan_summary, policy_summary

def plan_exit_success(code):
    return code in (0, 2)

def create_plan():
    os.umask(0o077)
    PRIVATE.mkdir(parents=True, exist_ok=True)
    binary, json_path = ROOT / "terraform/tfplan", ROOT / "terraform/tfplan.json"
    binary.unlink(missing_ok=True)
    json_path.unlink(missing_ok=True)
    record("plan-summary", {"result": "NOT RUN", "reason": "plan not completed"})
    record("plan-policy", {"result": "NOT RUN", "reason": "no successful plan"})
    try:
        command = tool("terraform") + ["-chdir=terraform"]
        # Logs can include sensitive values; keep them local/private and never echo them.
        with (PRIVATE / "terraform-plan.log").open("w", encoding="utf-8") as log:
            for args in (["init", "-input=false", "-lockfile=readonly"], ["validate", "-no-color"]):
                if run(command + args, stdout=log, stderr=log).returncode != 0:
                    raise ValueError("Initialization/validation failed")
            result = run(command + ["plan", "-input=false", "-no-color", "-detailed-exitcode", "-out=tfplan"], stdout=log, stderr=log)
            if not plan_exit_success(result.returncode):
                record("plan-summary", {"result": "FAIL", "exit_code": result.returncode})
                return False
            with json_path.open("w", encoding="utf-8") as output:
                shown = run(command + ["show", "-json", "tfplan"], stdout=output, stderr=log)
            if shown.returncode != 0:
                raise ValueError("Plan JSON export failed")
        summary = plan_summary(read_json(json_path), result.returncode)
        record("plan-summary", summary)
        print(f"Terraform plan: PASS (exit {result.returncode}); values withheld")
        return True
    except (OSError, ValueError, KeyError, TypeError):
        record("plan-summary", {"result": "FAIL", "reason": "Plan failed; inspect private local log"})
        return False

def plan_policy(path=None):
    os.umask(0o077)
    path = path or ROOT / "terraform/tfplan.json"
    try:
        PRIVATE.mkdir(parents=True, exist_ok=True)
        # Verify real-plan envelope, not the synthetic fixture subset.
        plan_summary(read_json(path), 0)
        with (PRIVATE / "plan-policy-raw.json").open("w", encoding="utf-8") as output, (PRIVATE / "plan-policy.log").open("w", encoding="utf-8") as errors:
            result = run(tool("conftest") + ["test", str(path), "--policy", "policies/terraform", "--output", "json"], stdout=output, stderr=errors)
        report = policy_summary(read_json(PRIVATE / "plan-policy-raw.json"), result.returncode)
    except (OSError, ValueError, KeyError, TypeError):
        report = {"result": "FAIL", "reason": "No valid plan or structured policy output"}
    record("plan-policy", report)
    print(f"Real-plan policy: {report['result']}; values/messages withheld")
    return report["result"] == "PASS"
