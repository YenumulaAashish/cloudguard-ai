"""Portable tool execution and JSON IO; no shell interpolation."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "reports/phase2"
PRIVATE = ROOT / "reports/private"

def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))

def tool(name):
    found = shutil.which(name)
    if found:
        return [found]
    suffix = ".exe" if os.name == "nt" else ""
    for candidate in (ROOT / ".tools" / name / (name + suffix), ROOT / ".tools" / (name + suffix)):
        if candidate.is_file():
            return [str(candidate)]
    if name == "checkov":
        folder = ROOT / ".venv" / ("Scripts" if os.name == "nt" else "bin")
        if (folder / "checkov").exists():
            return [str(folder / ("python.exe" if os.name == "nt" else "python")), str(folder / "checkov")]
    raise FileNotFoundError(f"Required tool unavailable: {name}")

def run(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, text=True, encoding="utf-8", errors="replace", **kwargs)

def python_script(name, *args):
    return [sys.executable, str(ROOT / "scripts" / name), *map(str, args)]
