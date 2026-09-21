"""Evidence is constructed from whitelisted fields, never copied from raw plans."""
from datetime import datetime, timezone
import hashlib
import os
import re
import subprocess
import uuid
from .runtime import ROOT, REPORTS, PRIVATE, read_json, write_json, run, tool

FILES = ("checks", "checkov", "checkov-exceptions", "policy-tests", "plan-summary", "plan-policy", "ci-safety")

def fingerprint():
    digest = hashlib.sha256()
    paths = [ROOT / "Makefile", ROOT / ".checkov.yml", ROOT / ".tflint.hcl", ROOT / ".tflint-core.hcl"]
    for directory in ("terraform", "policies", "scripts", "security", "tests", ".github", "bootstrap"):
        paths += [p for p in (ROOT / directory).rglob("*") if p.is_file() and p.suffix in {".tf", ".rego", ".py", ".sh", ".json", ".yml", ".yaml", ".hcl", ".tfvars"}
                  and ".terraform" not in p.parts and not p.name.startswith("tfplan")]
    for path in sorted(set(paths)):
        if path.exists():
            digest.update(path.relative_to(ROOT).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()

def begin(scope):
    scope = os.environ.get("CLOUDGUARD_SCOPE", scope)
    REPORTS.mkdir(parents=True, exist_ok=True)
    PRIVATE.mkdir(parents=True, exist_ok=True)
    for name in (*FILES, "summary"):
        (REPORTS / f"{name}.json").unlink(missing_ok=True)
    (REPORTS / "summary.md").unlink(missing_ok=True)
    context = {"run_id": str(uuid.uuid4()), "scope": scope,
               "started_at": datetime.now(timezone.utc).isoformat(), "source_digest": fingerprint()}
    write_json(REPORTS / "run-context.json", context)
    return context

def context():
    try:
        return read_json(REPORTS / "run-context.json")
    except (OSError, ValueError):
        return begin("local")

def record(name, value):
    ctx = context()
    write_json(REPORTS / f"{name}.json", {**value, "run_id": ctx["run_id"], "source_digest": fingerprint()})

def load(name):
    try:
        result = read_json(REPORTS / f"{name}.json")
        if result.get("run_id") != context()["run_id"] or result.get("source_digest") != fingerprint():
            return {"result": "NOT RUN", "reason": "stale evidence"}
        return result
    except (OSError, ValueError):
        return {"result": "NOT RUN", "reason": "no current evidence"}

def plan_summary(plan, exit_code):
    if exit_code not in (0, 2) or not isinstance(plan.get("planned_values", {}).get("root_module"), dict):
        raise ValueError("Not a successful complete Terraform plan")
    if not str(plan.get("format_version", "")).startswith("1.") or not plan.get("terraform_version"):
        raise ValueError("Unsupported or missing Terraform plan format/version")
    if plan.get("errored") or plan.get("complete") is False:
        raise ValueError("Errored or incomplete Terraform plan")
    counts = {"create": 0, "update": 0, "delete": 0, "read": 0, "no-op": 0, "forget": 0}
    resources = []
    for change in plan.get("resource_changes", []):
        actions = change["change"]["actions"]
        if not actions or any(action not in counts for action in actions):
            raise ValueError("Unsupported Terraform action")
        resources.append({"address": change["address"], "type": change["type"], "actions": actions})
        for action in actions:
            counts[action] += 1
    return {"result": "PASS", "exit_code": exit_code, "counts": counts, "resources": resources,
            "terraform_version": plan["terraform_version"], "format_version": plan["format_version"]}

def policy_summary(rows, exit_code):
    if not isinstance(rows, list) or not rows:
        raise ValueError("Missing structured Conftest results")
    failures = sum(len(row.get("failures", [])) for row in rows)
    exceptions = sum(len(row.get("exceptions", [])) for row in rows)
    warnings = sum(len(row.get("warnings", [])) for row in rows)
    successes = sum(row.get("successes", 0) for row in rows)
    if exit_code == 0 and (failures or exceptions or not successes):
        raise ValueError("Inconsistent Conftest status")
    # Do not export messages, metadata or filenames; they can carry sensitive values.
    return {"result": "PASS" if exit_code == 0 and not (failures or exceptions) else "FAIL",
            "exit_code": exit_code, "passed": successes, "failed": failures,
            "warnings": warnings, "exceptions": exceptions}

def version(name):
    try:
        flag = "version" if name == "opa" else "--version"
        result = run(tool(name) + [flag], capture_output=True)
        match = re.search(r'\d+\.\d+\.\d+', result.stdout)
        return match[0] if result.returncode == 0 and match else None
    except OSError:
        return None

def git(*args):
    result = run(["git", *args], capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else None

def generate():
    ctx = context()
    results = {name: load(name) for name in FILES}
    required = ("checks", "checkov", "checkov-exceptions", "policy-tests", "ci-safety")
    if ctx["scope"] == "authenticated-plan":
        required += ("plan-summary", "plan-policy")
    statuses = [results[n].get("result", "NOT RUN") for n in required]
    outcome = "FAIL" if "FAIL" in statuses else ("NOT RUN" if "NOT RUN" in statuses else "PASS")
    if os.environ.get("CI_JOB_STATUS") in {"failure", "cancelled"}:
        outcome = "FAIL"
    lock = ROOT / "terraform/.terraform.lock.hcl"
    provider = re.search(r'provider "registry.terraform.io/hashicorp/aws"\s*\{\s*version\s*=\s*"([^"]+)"', lock.read_text()) if lock.exists() else None
    summary = {"result": outcome, "context": ctx, "git": {
        "sha": os.environ.get("GITHUB_SHA") or git("rev-parse", "HEAD"),
        "ref": os.environ.get("GITHUB_REF") or git("symbolic-ref", "--short", "HEAD"),
        "dirty": bool(git("status", "--porcelain")),
    }, "ci_run_id": os.environ.get("GITHUB_RUN_ID"), "aws_region": "ap-south-1",
       "versions": {name: version(name) for name in ("terraform", "checkov", "opa", "conftest", "tflint")},
       "aws_provider_version": provider[1] if provider else None, "checks": results}
    write_json(REPORTS / "summary.json", summary)
    lines = ["# CloudGuard Phase 2 evidence", "", f"Result: **{outcome}**", "", f"Scope: {ctx['scope']}",
             f"Commit: {summary['git']['sha'] or 'unavailable (no commit)'}", "", "| Gate | Result |", "|---|---|"]
    lines += [f"| {name} | {value.get('result', 'NOT RUN')} |" for name, value in results.items()]
    lines += ["", "Raw plans, Terraform values, source snippets and policy messages are excluded.",
              "Missing or stale evidence is NOT RUN. This report contains no experimental accuracy metrics."]
    (REPORTS / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Evidence: {outcome}; reports/phase2/summary.json")
    return summary
