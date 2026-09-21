"""Mandatory Checkov source scan and exact exception verification."""
import subprocess
from .runtime import ROOT, PRIVATE, tool, run, read_json
from .exceptions import verify, terraform_report
from .evidence import record

def security_scan():
    PRIVATE.mkdir(parents=True, exist_ok=True)
    raw_path = PRIVATE / "checkov-raw.json"
    try:
        with raw_path.open("w", encoding="utf-8") as output, (PRIVATE / "checkov.log").open("w", encoding="utf-8") as errors:
            result = run(tool("checkov") + ["-d", "terraform", "--config-file", ".checkov.yml", "--output", "json"], stdout=output, stderr=errors)
        raw = read_json(raw_path)
        report = terraform_report(raw)
        counts = report["summary"]
        sanitized = {"result": "PASS" if result.returncode == 0 and counts["failed"] == 0 and counts["parsing_errors"] == 0 else "FAIL",
                     "exit_code": result.returncode,
                     **{k: counts[k] for k in ("passed", "failed", "skipped", "parsing_errors", "resource_count")},
                     "checks": {}}
        for group in ("passed_checks", "failed_checks", "skipped_checks"):
            sanitized["checks"][group] = [{"rule_id": c["check_id"], "resource": c["resource"]} for c in report["results"][group]]
        print(f"Checkov: {sanitized['result']} ({counts['passed']} passed, {counts['failed']} failed, {counts['skipped']} skipped)")
        for group in ("failed_checks", "skipped_checks"):
            for c in sanitized["checks"][group]:
                print(f"  {group}: {c['rule_id']} {c['resource']}")
    except (OSError, ValueError, KeyError, TypeError):
        raw = {}
        sanitized = {"result": "FAIL", "reason": "Checkov unavailable or report incomplete; inspect private local log"}
    contract = verify(ROOT, raw)
    record("checkov", sanitized)
    record("checkov-exceptions", contract)
    print(f"Exception contract: {contract['result']}")
    for error in contract["errors"]:
        print(error)
    return sanitized["result"] == contract["result"] == "PASS"
