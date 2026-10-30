"""Offline composition of Phase 3; no new policy, scoring or advisory engine."""
from copy import deepcopy
import os
from pathlib import Path
from .analysis import analyze_security, consistent_risk, validate_remediation
from .analysis import render_markdown as advisory_markdown
from .findings import build_report, serialize
from .pr_reporting import GATES, summarize, render_markdown, validate_summary
from .pr_evidence import current_policy
from .risk import assess_risk, load_model, read_document
from .runtime import ROOT, REPORTS, PRIVATE

SCHEMAS = {"normalized": "normalized-findings", "risk": "risk-report",
           "advisory": "remediation-report", "summary": "pr-summary", "manifest": "phase3-evidence"}
PRIVATE_NAMES = ("normalized.json", "risk.json", "advisory.json", "advisory.md")
PUBLIC_NAMES = ("pr-summary.json", "pr-summary.md", "phase3-evidence.json")


class IntegrationError(ValueError):
    """No source values or validation details in public diagnostics."""


def require(condition):
    if not condition:
        raise IntegrationError("Phase 3 integrity validation failed")


def schema_validate(value, name):
    # Already installed with the pinned Checkov toolchain. Never auto-install.
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry
        from referencing.exceptions import NoSuchResource
    except ImportError:
        raise IntegrationError("Phase 3 requires jsonschema from the existing Checkov toolchain") from None

    def no_remote(uri):
        raise NoSuchResource(ref=uri)

    schema = read_document(ROOT / "security" / (SCHEMAS[name] + ".schema.json"))
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, registry=Registry(retrieve=no_remote)).validate(value)
    except Exception:
        raise IntegrationError("Phase 3 schema validation failed") from None


def validate_chain(inputs, chain, policy, model):
    require(type(chain) is dict and set(chain) == {"normalized", "risk", "advisory", "summary"})
    for name, value in chain.items():
        schema_validate(value, name)
    n, r, a, s = (chain[k] for k in ("normalized", "risk", "advisory", "summary"))
    require(serialize(n) == serialize(build_report(deepcopy(inputs))))
    consistent_risk(n, r, model)
    validate_remediation(a, r)
    require(a["analysis_mode"] == "offline")
    validate_summary(s)
    require(serialize(s) == serialize(summarize(n, r, a, policy=policy, model=model)))


def build_chain(inputs, model, evidence=False):
    n = build_report(deepcopy(inputs))
    schema_validate(n, "normalized")
    r = assess_risk(n, model)
    schema_validate(r, "risk")
    a = analyze_security(n, r, mode="offline", model=model)
    schema_validate(a, "advisory")
    policy = current_policy(n) if evidence else {key: "UNKNOWN" for key in GATES}
    s = summarize(n, r, a, policy=policy, model=model)
    schema_validate(s, "summary")
    chain = {"normalized": n, "risk": r, "advisory": a, "summary": s}
    validate_chain(inputs, chain, policy, model)
    return chain


def payloads(chain):
    return ({"normalized.json": serialize(chain["normalized"]), "risk.json": serialize(chain["risk"]),
             "advisory.json": serialize(chain["advisory"]), "advisory.md": advisory_markdown(chain["advisory"])},
            {"pr-summary.json": serialize(chain["summary"]), "pr-summary.md": render_markdown(chain["summary"])})


def evidence_snapshot():
    """Ephemeral exact bytes reuse existing run/fingerprint records; no new hashes.

    Nothing in this snapshot is exported. Changing evidence during a run is an
    integrity error; initially missing/stale evidence still maps to UNKNOWN.
    """
    paths = [REPORTS / (name + ".json") for name in
             ("run-context", "checkov", "checkov-exceptions", "policy-tests", "plan-policy")]
    paths += [PRIVATE / "checkov-raw.json", PRIVATE / "plan-policy-raw.json"]
    return tuple(path.read_bytes() if path.exists() else None for path in paths)


def prepare(inputs, model=None, evidence=False):
    inputs = deepcopy(inputs)
    model = load_model() if model is None else deepcopy(model)
    before = evidence_snapshot() if evidence else None
    chain = build_chain(inputs, model, evidence)
    first = payloads(chain)
    repeated = build_chain(inputs, model, evidence)
    require(first == payloads(repeated))
    if evidence:
        require(before == evidence_snapshot())
    manifest = {"schema_version": "1.0", "phase": "3", "informational_only": True,
                "completion": "COMPLETE", "advisory_mode": "offline",
                "components": {key: "PASS" for key in ("normalization", "risk", "advisory", "pr_reporting")},
                "validation": {key: "PASS" for key in ("schemas", "cross_phase_consistency", "byte_reproduction")}}
    schema_validate(manifest, "manifest")
    private, public = first
    public["phase3-evidence.json"] = serialize(manifest)
    require(all(len(value.encode("utf-8")) <= 4096 for value in public.values()))
    return chain, private, public


def output_directory(path, boundary):
    path, boundary = Path(path).resolve(), Path(boundary).resolve()
    require(path != boundary and boundary in path.parents)
    require(not path.exists())
    return path


def write_file(path, text):
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())


def publish(inputs, private_dir, public_dir, model=None, evidence=False, root=ROOT):
    """Reserve fresh directories; publish completion last, rollback owned files.

    No recursive deletion, overwrite or shared-output directory is permitted.
    A complete manifest plus a successful invocation is the completion protocol.
    """
    private_dir = output_directory(private_dir, root / "reports/private")
    public_dir = output_directory(public_dir, root / "reports/sanitized")
    model = load_model() if model is None else deepcopy(model)
    snapshot = evidence_snapshot() if evidence else None
    chain, private, public = prepare(inputs, model, evidence)
    if evidence:
        require(snapshot == evidence_snapshot())
    created_dirs, created_files, complete = [], [], False
    try:
        for directory in (private_dir, public_dir):
            directory.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory.mkdir(mode=0o700)  # Atomic no-overwrite reservation.
            created_dirs.append(directory)
        # All outputs are validated before any file is made visible.
        for directory, values in ((private_dir, private), (public_dir, public)):
            for name, text in values.items():
                if name == "phase3-evidence.json":
                    continue
                path = directory / name
                created_files.append(path)
                write_file(path, text)
        restored = {"normalized": read_document(private_dir / "normalized.json"),
                    "risk": read_document(private_dir / "risk.json"),
                    "advisory": read_document(private_dir / "advisory.json"),
                    "summary": read_document(public_dir / "pr-summary.json")}
        validate_chain(inputs, restored, chain["summary"]["policy"], model)
        for directory, values in ((private_dir, private), (public_dir, public)):
            for name, text in values.items():
                if name != "phase3-evidence.json":
                    require((directory / name).read_bytes() == text.encode("utf-8"))
        if evidence:
            require(snapshot == evidence_snapshot())
            require(chain["summary"]["policy"] == current_policy(chain["normalized"]))
        # Rename a fully written manifest in the exclusively reserved directory.
        temporary = public_dir / ".phase3-evidence.tmp"
        created_files.append(temporary)
        write_file(temporary, public["phase3-evidence.json"])
        require(temporary.read_bytes() == public["phase3-evidence.json"].encode("utf-8"))
        final = public_dir / "phase3-evidence.json"
        require(not final.exists())
        temporary.rename(final)
        created_files.append(final)
        complete = True
    finally:
        if not complete:
            for path in reversed(created_files):
                path.unlink(missing_ok=True)
            for directory in reversed(created_dirs):
                directory.rmdir()
    return chain["summary"]
