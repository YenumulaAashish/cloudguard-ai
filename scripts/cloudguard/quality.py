"""Offline validation tasks. All failures propagate; no cloud API credentials needed."""
import ast
import os
import subprocess
import sys
from .runtime import ROOT, PRIVATE, tool, run
from .evidence import record

def quality():
    PRIVATE.mkdir(parents=True, exist_ok=True)
    tasks = []
    tf = tool("terraform")
    tasks.append(("terraform-fmt", tf + ["fmt", "-check", "-recursive", "terraform"]))
    tasks.append(("bootstrap-fmt", tf + ["fmt", "-check", "-recursive", "bootstrap"]))
    for directory in ("terraform", "bootstrap/aws-plan-role"):
        tasks += [(f"{directory}-init", tf + [f"-chdir={directory}", "init", "-backend=false", "-input=false", "-lockfile=readonly"]),
                  (f"{directory}-validate", tf + [f"-chdir={directory}", "validate", "-no-color"])]
    config = ".tflint.hcl" if os.environ.get("TFLINT_AWS") == "1" else ".tflint-core.hcl"
    tasks.append(("tflint", tool("tflint") + ["--chdir=terraform", "--recursive", f"--config={ROOT / config}"]))
    tasks.append(("python-unit-tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests/unit", "-v"]))
    results = []
    for name, command in tasks:
        try:
            with (PRIVATE / (name.replace("/", "-") + ".log")).open("w", encoding="utf-8") as log:
                result = run(command, stdout=log, stderr=log)
            status = "PASS" if result.returncode == 0 else "FAIL"
        except OSError:
            status = "FAIL"
        results.append({"name": name, "result": status})
        print(f"{name}: {status}", flush=True)
    if os.environ.get("TFLINT_AWS") != "1":
        results.append({"name": "tflint-aws", "result": "NOT RUN"})
        print("TFLint AWS plugin: NOT RUN (set TFLINT_AWS=1 to require it)")
    for path in (ROOT / "scripts").rglob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    report = {"result": "FAIL" if any(r["result"] == "FAIL" for r in results) else "PASS", "tasks": results}
    record("checks", report)
    return report["result"] == "PASS"
