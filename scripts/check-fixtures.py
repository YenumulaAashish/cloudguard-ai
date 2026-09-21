"""Require the expected policy failure, not merely a nonzero process exit."""
import json
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
expected = {"public-ssh": "SSH:", "public-s3": "S3_PUBLIC:",
            "missing-encryption": "S3_ENCRYPTION:", "missing-tags": "TAGS:",
            "wildcard-iam": "IAM:"}
for name, prefix in expected.items():
    result = subprocess.run(["conftest", "test", str(root / "tests/fixtures/insecure" / (name + ".json")),
                             "--policy", str(root / "policies/terraform"), "--output", "json"],
                            capture_output=True, text=True)
    if result.returncode != 1:
        raise SystemExit(f"FAIL {name}: expected policy rejection, got {result.returncode}: {result.stderr}")
    rows = json.loads(result.stdout)
    failures = [f["msg"] for row in rows for f in row.get("failures", [])]
    if not failures or any(not msg.startswith(prefix) for msg in failures):
        raise SystemExit(f"FAIL {name}: unexpected diagnostics {failures}")
    print(f"PASS {name}: expected {prefix} rejection")
