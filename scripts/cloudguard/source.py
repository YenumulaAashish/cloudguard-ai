"""Conservative HCL block/annotation reader for this repository's local modules.

This is not an HCL evaluator. Dynamic/remote module sources and JSON Terraform
are rejected by the exception contract rather than guessed.
"""
from collections import Counter
from pathlib import Path
import re

TOKEN = re.compile(r'(?P<comment>\#[^\n]*|//[^\n]*|/\*[\s\S]*?\*/)|(?P<string>"(?:\\.|[^"\\])*")|(?P<word>[A-Za-z_][\w-]*)|(?P<brace>[{}])|(?P<other>[^\s])')
SKIP = re.compile(r'checkov\s*:\s*skip\s*=\s*([^:\s]+)', re.I)

def blocks(text):
    if re.search(r'<<-?\s*\w+', text):
        raise ValueError("Heredoc syntax needs explicit exception-parser support")
    tokens = list(TOKEN.finditer(text))
    significant = [t for t in tokens if t.lastgroup != "comment"]
    result = []
    depth = 0
    i = 0
    while i < len(significant):
        token = significant[i]
        if depth == 0 and token.group() in {"resource", "module"}:
            count = 2 if token.group() == "resource" else 1
            labels = significant[i+1:i+1+count]
            if len(labels) != count or any(t.lastgroup != "string" for t in labels):
                raise ValueError("Nonliteral block labels are unsupported")
            start = i + count + 1
            if significant[start].group() != "{":
                raise ValueError("Malformed block")
            j, level = start+1, 1
            while j < len(significant) and level:
                level += (significant[j].group() == "{") - (significant[j].group() == "}")
                j += 1
            if level:
                raise ValueError("Unbalanced HCL block")
            result.append((token.group(), [t.group()[1:-1] for t in labels], significant[start].end(), significant[j-1].start()))
            i = j
            continue
        depth += (token.group() == "{") - (token.group() == "}")
        i += 1
    return result, [t for t in tokens if t.lastgroup == "comment"]

def annotations(root):
    root = Path(root).resolve()
    terraform = root / "terraform"
    found, visited, active = [], set(), set()
    def visit(folder, prefix):
        folder = folder.resolve()
        if not folder.is_relative_to(terraform) or folder in active:
            raise ValueError("Module escapes Terraform tree or forms a cycle")
        active.add(folder)
        if list(folder.glob("*.tf.json")):
            raise ValueError("Terraform JSON requires explicit exception-parser support")
        for path in sorted(folder.glob("*.tf")):
            visited.add(path.resolve())
            text = path.read_text(encoding="utf-8")
            parsed, comments = blocks(text)
            for comment in comments:
                if "checkov" not in comment.group().lower():
                    continue
                matches = list(SKIP.finditer(comment.group()))
                if not matches:
                    if "skip" in comment.group().lower():
                        raise ValueError(f"Unrecognized Checkov annotation in {path.name}")
                    continue
                owners = [b for b in parsed if b[0] == "resource" and b[2] <= comment.start() < b[3]]
                if len(owners) != 1:
                    raise ValueError("Skip outside a resource block")
                address = prefix + ".".join(owners[0][1])
                for match in matches:
                    found.append((match[1], address))
            for kind, labels, start, end in parsed:
                if kind == "module":
                    source = re.search(r'\bsource\s*=\s*"([^"$]+)"', text[start:end])
                    if not source or not source[1].startswith("./"):
                        raise ValueError("Only literal local module sources are accepted")
                    visit(folder / source[1], prefix + "module." + labels[0] + ".")
        active.remove(folder)
    visit(terraform, "")
    for path in terraform.rglob("*.tf"):
        if ".terraform" in path.parts:
            continue
        if path.resolve() not in visited and SKIP.search(path.read_text(encoding="utf-8")):
            raise ValueError("Skip in an unreferenced module")
    # Bootstrap is validated separately, but it is not an exception escape hatch.
    outside = list(root.glob("*.tf")) + list((root / "bootstrap").rglob("*.tf"))
    for path in outside:
        if ".terraform" not in path.parts and SKIP.search(path.read_text(encoding="utf-8")):
            raise ValueError("Skip outside the approved workload Terraform root")
    return Counter(found)
