"""Offline validation tasks. All failures propagate; no cloud API credentials needed."""
import ast
import json
import os
import subprocess
import sys
from .runtime import ROOT, PRIVATE, tool, run
from .evidence import record

# Only fixed diagnostic text is public. Terraform detail/snippet/expression fields
# can contain literal configuration values, even during offline validation.
SAFE_SUMMARIES = {
    "Unsupported Terraform Core version", "Unsupported argument",
    "Missing required argument", "Invalid value for input variable",
    "Invalid reference", "Reference to undeclared resource",
    "Reference to undeclared input variable", "Unsupported attribute",
    "Invalid function argument", "Invalid expression", "Invalid type specification",
    "Module not installed", "Missing required provider", "Failed to load plugin schemas",
    "Inconsistent dependency lock file", "Invalid resource type",
    "Duplicate resource configuration", "Unsupported block type",
}
CHECKSUM_ERROR = (
    "registry.terraform.io/hashicorp/aws: the cached package for "
    "registry.terraform.io/hashicorp/aws 6.65.0 (in .terraform/providers) "
    "does not match any of the checksums recorded in the dependency lock file"
)

def validation_diagnostics(output):
    """Return useful allowlisted diagnostics without source values or raw stderr."""
    try:
        document = json.loads(output)
        diagnostics = document["diagnostics"]
        if not isinstance(diagnostics, list):
            raise ValueError("Invalid diagnostics")
    except (ValueError, KeyError, TypeError):
        return ["Terraform returned no usable JSON diagnostics; raw output retained privately."]
    messages = []
    for diagnostic in diagnostics:
        if not isinstance(diagnostic, dict):
            continue
        summary = diagnostic.get("summary", "")
        detail = diagnostic.get("detail", "")
        if CHECKSUM_ERROR in (summary, detail):
            messages.append("Error: " + CHECKSUM_ERROR)
            messages.append("Regenerate verified Linux and Windows hashes with terraform providers lock.")
        elif isinstance(summary, str) and summary in SAFE_SUMMARIES:
            messages.append("Terraform diagnostic: " + summary)
        else:
            messages.append("Terraform diagnostic withheld (not in the safe diagnostic allowlist).")
    return messages or ["Terraform failed without structured diagnostics; raw output retained privately."]

def quality():
    PRIVATE.mkdir(parents=True, exist_ok=True)
    tasks = []
    tf = tool("terraform")
    tasks.append(("terraform-fmt", tf + ["fmt", "-check", "-recursive", "terraform"]))
    tasks.append(("bootstrap-fmt", tf + ["fmt", "-check", "-recursive", "bootstrap"]))
    for directory in ("terraform", "bootstrap/aws-plan-role"):
        tasks += [(f"{directory}-init", tf + [f"-chdir={directory}", "init", "-backend=false", "-input=false", "-lockfile=readonly"]),
                  (f"{directory}-validate", tf + [f"-chdir={directory}", "validate", "-json", "-no-color"])]
    config = ".tflint.hcl" if os.environ.get("TFLINT_AWS") == "1" else ".tflint-core.hcl"
    tasks.append(("tflint", tool("tflint") + ["--chdir=terraform", "--recursive", f"--config={ROOT / config}"]))
    tasks.append(("python-unit-tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests/unit", "-v"]))
    results = []
    for name, command in tasks:
        try:
            log_path = PRIVATE / (name.replace("/", "-") + ".log")
            with log_path.open("w", encoding="utf-8") as log:
                result = run(command, stdout=log, stderr=log)
            status = "PASS" if result.returncode == 0 else "FAIL"
            if status == "FAIL" and name.endswith("-validate"):
                # Startup errors may not be JSON; never echo that raw output.
                for message in validation_diagnostics(log_path.read_text(encoding="utf-8")):
                    print(f"{name}: {message}", flush=True)
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
