"""Aggregate reporting only: no network, execution, policy or risk decisions."""
import os
from pathlib import Path
from .analysis import AnalysisError, consistent_risk, validate_remediation
from .findings import serialize
from .risk import CATEGORIES, RiskInputError, integer, json_value

MARKER = "<!-- cloudguard-ai-security-review -->"
TRUST_RULE = "Deterministic tools decide. AI explains. PR reporting informs."
NOTICE = "A PR report is informational and does not replace CI security gate conclusions."
GATES = ("checkov", "opa_conftest", "exception_contract", "policy_tests")
STATES = ("PASS", "FAIL", "UNKNOWN")
MAX_COUNT = 1000000
MAX_OUTPUT_BYTES = 4096


class ReportingError(ValueError):
    """Value-free public diagnostics only."""


def require(condition):
    if not condition:
        raise ReportingError("Invalid or inconsistent PR reporting input")


def keys(value, names):
    require(type(value) is dict and set(value) == set(names))


def validate_policy(policy):
    keys(policy, GATES)
    require(all(type(v) is str and v in STATES for v in policy.values()))


def validate_summary(report):
    keys(report, ("schema_version", "generated_by", "informational_only", "policy", "findings", "risk", "advisory"))
    require(report["schema_version"] == "1.0" and report["generated_by"] == "cloudguard-ai"
            and report["informational_only"] is True)
    validate_policy(report["policy"])
    keys(report["findings"], ("total", "failed", "approved_exceptions"))
    counts = report["findings"]
    require(all(integer(n, 0, MAX_COUNT) for n in counts.values()))
    require(counts["failed"] + counts["approved_exceptions"] <= counts["total"])
    keys(report["risk"], ("score", "category", "requires_review"))
    risk = report["risk"]
    require(integer(risk["score"], 0, 100) and type(risk["category"]) is str
            and risk["category"] in CATEGORIES and type(risk["requires_review"]) is bool)
    keys(report["advisory"], ("mode", "findings_reviewed"))
    advice = report["advisory"]
    require(type(advice["mode"]) is str and advice["mode"] in ("offline", "ai", "NOT_RUN"))
    require(integer(advice["findings_reviewed"], 0, MAX_COUNT)
            and advice["findings_reviewed"] == (0 if advice["mode"] == "NOT_RUN" else counts["total"]))
    require(len(serialize(report).encode("utf-8")) <= MAX_OUTPUT_BYTES)


def summarize(normalized, risk_report, remediation=None, policy=None, model=None):
    """Policy comes only from the evidence adapter (or an explicit trusted caller)."""
    try:
        risk = consistent_risk(normalized, risk_report, model)
        mode, reviewed = "NOT_RUN", 0
        if remediation is not None:
            json_value(remediation)
            require(type(remediation) is dict)
            validate_remediation(remediation, risk)
            mode, reviewed = remediation["analysis_mode"], len(remediation["findings"])
        policy = {key: "UNKNOWN" for key in GATES} if policy is None else policy
        validate_policy(policy)
        report = {"schema_version": "1.0", "generated_by": "cloudguard-ai", "informational_only": True,
                  "policy": {key: policy[key] for key in GATES},
                  "findings": {key: risk["summary"][key] for key in ("total", "failed", "approved_exceptions")},
                  "risk": {key: risk["overall"][key] for key in ("score", "category", "requires_review")},
                  "advisory": {"mode": mode, "findings_reviewed": reviewed}}
        validate_summary(report)
        return report
    except (AnalysisError, RiskInputError, KeyError, TypeError, RecursionError):
        raise ReportingError("Invalid or inconsistent private reports; no summary generated") from None


def render_markdown(report):
    validate_summary(report)
    policy, counts, risk, advice = (report[k] for k in ("policy", "findings", "risk", "advisory"))
    lines = [MARKER, "## CloudGuard-AI Security Review", "", "### Policy Enforcement", "",
             "| Check | Status |", "| --- | --- |"]
    for label, key in (("Checkov", "checkov"), ("OPA / Conftest real-plan policy", "opa_conftest"),
                       ("Exception Contract", "exception_contract"), ("OPA / Conftest tests", "policy_tests")):
        lines.append(f"| {label} | {policy[key]} |")
    lines += ["", "### Findings", "", "| Type | Count |", "| --- | ---: |",
              f"| Total reported findings | {counts['total']} |", f"| Failed | {counts['failed']} |",
              f"| Approved Exceptions | {counts['approved_exceptions']} |", "", "### Risk Assessment", "",
              "| Metric | Result |", "| --- | --- |", f"| Overall Risk | {risk['category']} |",
              f"| Risk Score | {risk['score']} |", f"| Review Required | {'YES' if risk['requires_review'] else 'NO'} |",
              "", "### Advisory Analysis", "",
              "Mode: " + {"offline": "Offline advisory", "ai": "AI advisory", "NOT_RUN": "Not performed"}[advice['mode']],
              "", f"Findings reviewed: {advice['findings_reviewed']}", "", "> " + TRUST_RULE, "", "> " + NOTICE,
              "", "UNKNOWN means no reliable matching evidence. Policy tests do not establish real-plan compliance."]
    output = "\n".join(lines) + "\n"
    require(len(output.encode("utf-8")) <= MAX_OUTPUT_BYTES)
    return output


def write_outputs(report, output, markdown=None):
    """Exclusive writes; roll back only files created by this invocation."""
    validate_summary(report)
    outputs = [(Path(output), serialize(report))]
    if markdown is not None:
        outputs.append((Path(markdown), render_markdown(report)))
    require(len({p.resolve() for p, _ in outputs}) == len(outputs))
    # Publishable files must not live inside any reports/private subtree.
    for path, _ in outputs:
        parts = [p.casefold() for p in path.resolve().parts]
        require(not any(a == "reports" and b == "private" for a, b in zip(parts, parts[1:])))
    created, complete = [], False
    try:
        for path, payload in outputs:
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(payload)
        complete = True
    finally:
        if not complete:
            for path in reversed(created):
                path.unlink(missing_ok=True)
