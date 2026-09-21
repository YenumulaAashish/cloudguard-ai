"""Static guard for ordinary CI commands, not a malicious-code sandbox."""
import ast
from pathlib import Path
import re

SUPPRESSION = re.compile(r'--(?:soft-fail(?:-on)?|skip-check|skip-framework)(?:\b|=)|\b(?:CKV|CHECKOV)_[A-Z_]*(?:SKIP|SOFT_FAIL)[A-Z_]*', re.I)
DEPLOY = re.compile(r'\bterraform(?:\.exe)?["\x27]?\s+(?:-chdir(?:=|\s+)\S+\s+)?(?:apply|destroy)\b|\b(?:tofu|terragrunt)\s+(?:apply|destroy)\b|--?auto-approve\b', re.I)

def executable_text(path):
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".py":
        tree = ast.parse(text)
        chunks = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        chunks += [" ".join(n.value for n in node.elts if isinstance(n, ast.Constant) and isinstance(n.value, str))
                   for node in ast.walk(tree) if isinstance(node, (ast.List, ast.Tuple))]
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                chunks.append(" ".join(n.value for n in ast.walk(node)
                                       if isinstance(n, ast.Constant) and isinstance(n.value, str)))
        return "\n".join(chunks)
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#")).replace("\\\n", " ")

def inspect(root, suppression=False):
    root = Path(root)
    paths = [root / "Makefile"]
    for folder in (root / "scripts", root / ".github"):
        paths.extend(p for p in folder.rglob("*") if p.suffix in {".sh", ".py", ".yml", ".yaml", ".ps1", ".cmd", ".bat"})
    errors = []
    for path in paths:
        if not path.exists():
            continue
        text = executable_text(path)
        pattern = SUPPRESSION if suppression else DEPLOY
        if pattern.search(text):
            errors.append(f"Forbidden {'suppression' if suppression else 'deployment'} command in {path.relative_to(root)}")
        if not suppression and path.suffix in {".yml", ".yaml"} and re.search(r'\bpull_request_target\b', text):
            errors.append(f"Unsafe privileged PR trigger in {path.relative_to(root)}")
        if path.suffix in {".yml", ".yaml"} and re.search(r'continue-on-error:\s*(?!false\b)\S+', text):
            errors.append(f"Failure-masking CI step in {path.relative_to(root)}")
    if suppression:
        config_paths = set(root.glob("*checkov*"))
        for folder in (root / "security", root / ".github", root / "scripts"):
            config_paths.update(p for p in folder.rglob("*") if p.suffix in {".yml", ".yaml", ".json", ".toml"})
        for path in config_paths:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            for line in text.splitlines():
                if line.lstrip().startswith("#"):
                    continue
                if re.search(r'["\x27]?(?:skip[-_]check|skip[-_]framework|check)["\x27]?\s*:', line, re.I):
                    errors.append(f"Global check filtering in {path.name}")
                if re.search(r'["\x27]?soft[-_]fail(?:[-_]on)?["\x27]?\s*:', line, re.I) and not re.search(r':\s*false\s*[,}]?\s*$', line, re.I):
                    errors.append(f"Soft failure configuration in {path.name}")
    return errors
