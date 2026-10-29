"""Immutable deterministic context plus validated, private advisory enrichment."""
from copy import deepcopy
import json
import re
from .advice import ANALYSIS_FIELDS, CONCERNS, OfflineProvider, build_request
from .findings import serialize
from .risk import RiskInputError, assess_risk, json_value

NOTICE = "AI-generated remediation is advisory and does not override policy enforcement or risk scoring."
TRUST_RULE = "Deterministic tools decide. AI explains."
IDENTITY_FIELDS = ("source", "control_id", "resource", "status", "severity", "exception")
TEXT_FIELDS = ("summary", "why_it_matters", "potential_impact", "recommended_action")
UNSAFE_TEXT = re.compile(
    r"\b(?:terraform|tofu|terragrunt)(?:\.exe)?(?:\s+-chdir(?:=|\s+)\S+)?\s+(?:apply|destroy)\b"
    r"|--?auto-approve\b|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|\b(?:gate|policy|checkov|conftest|opa)\s+(?:has\s+)?(?:passed|approved)\b"
    r"|\b(?:set|change|override|replace|reset|lower)\s+(?:the\s+)?"
    r"(?:risk(?:\s+(?:score|category))?|score|category|status|exception\s+state|gate\s+decision|requires_review)\b"
    r"|\bapprove\s+(?:(?:the|an?|this|any|all)\s+)?exceptions?\b", re.I)


class AnalysisError(ValueError):
    """Fixed public diagnostics; never expose provider exceptions or raw values."""


def require(condition, message):
    if not condition:
        raise AnalysisError(message)


def consistent_risk(normalized, risk_report, model=None):
    """Reuse Phase 3.2's complete identity and scoring checks, including duplicates."""
    try:
        expected = assess_risk(normalized, model)
        json_value(risk_report)
        require(isinstance(risk_report, dict), "Expected a risk report object")
        actual = deepcopy(risk_report)
        require(isinstance(actual.get("findings"), list)
                and all(isinstance(f, dict) for f in actual["findings"]), "Invalid risk findings")
        require(isinstance(actual.get("sources"), list)
                and all(isinstance(s, str) for s in actual["sources"]), "Invalid risk sources")
        actual["findings"].sort(key=serialize)
        actual["sources"].sort()
        require(serialize(actual) == serialize(expected), "Normalized and risk reports are inconsistent")
        return expected
    except (RiskInputError, TypeError, RecursionError):
        raise AnalysisError("Invalid deterministic input or unsupported schema/model") from None


def deterministic_context(risk):
    return {key: deepcopy(risk[key]) for key in (
        "input_schema_version", "schema_version", "risk_model_version", "risk_model_sha256",
        "overall", "summary", "gate_decision")}


def provider_findings(findings):
    rows = []
    for index, item in enumerate(findings, 1):
        control = item["control_id"] if (item["source"], item["control_id"]) in CONCERNS else None
        rows.append({"finding_id": f"finding-{index:06d}", "source": item["source"],
                     "control_id": control, "resource": f"resource-{index:06d}" if item["resource"] is not None else None,
                     "status": item["status"] if item["status"] in {"failed", "warning", "skipped", "passed"} else "unknown",
                     "severity": item["severity"], "exception": item["exception"], "risk": deepcopy(item["risk"])})
    return rows


def safe_text(value, nullable=False):
    if nullable and value is None:
        return
    require(isinstance(value, str) and bool(value.strip()) and len(value) <= 12000, "Invalid advisory text")
    require(not any(ord(c) < 32 and c not in "\n\r\t" for c in value), "Invalid advisory control characters")
    require(UNSAFE_TEXT.search(value) is None, "Unsafe or authoritative provider content rejected")


def validate_analysis(value):
    require(isinstance(value, dict) and set(value) == set(ANALYSIS_FIELDS), "Invalid analysis fields")
    for field in TEXT_FIELDS:
        safe_text(value[field])
    safe_text(value["terraform_example"], nullable=True)
    steps = value["verification_steps"]
    require(isinstance(steps, list) and 1 <= len(steps) <= 20, "Invalid verification steps")
    for step in steps:
        safe_text(step)
    require(value["confidence"] in ("LOW", "MEDIUM", "HIGH"), "Invalid advice confidence")


def validate_response(response, expected_ids):
    try:
        json_value(response)
    except (RiskInputError, RecursionError):
        raise AnalysisError("Provider returned invalid JSON values") from None
    require(isinstance(response, dict) and set(response) == {"schema_version", "findings"}
            and response["schema_version"] == "1.0", "Invalid provider response envelope")
    require(isinstance(response["findings"], list), "Invalid provider findings")
    rows = {}
    for row in response["findings"]:
        require(isinstance(row, dict) and set(row) == {"finding_id", "analysis"}, "Invalid provider finding fields")
        identifier = row["finding_id"]
        require(isinstance(identifier, str) and identifier in expected_ids and identifier not in rows,
                "Provider finding identities are missing, duplicated or unexpected")
        validate_analysis(row["analysis"])
        rows[identifier] = deepcopy(row["analysis"])
    require(set(rows) == set(expected_ids), "Provider response omitted findings")
    return rows


def analyze_security(normalized, risk_report, mode="offline", provider=None, model=None):
    risk = consistent_risk(normalized, risk_report, model)
    require(mode in ("offline", "ai"), "Unsupported analysis mode")
    if mode == "offline":
        require(provider is None, "Offline mode cannot use an external provider")
        provider = OfflineProvider()
    else:
        require(provider is not None, "AI mode requested but no provider is configured; explicitly select offline mode")
    try:
        name = getattr(provider, "name", None)
    except Exception:
        raise AnalysisError("Advisory provider failed; no report generated") from None
    require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name) is not None,
            "Invalid provider identifier")
    context = deterministic_context(risk)
    minimized = provider_findings(risk["findings"])
    request = build_request(context, minimized)
    try:
        # A provider can modify only its own copy; it never receives core objects.
        response = (provider.analyze(deepcopy(request)) if minimized else
                    {"schema_version": "1.0", "findings": []})
    except Exception:
        raise AnalysisError("Advisory provider failed; no report generated") from None
    advice = validate_response(response, {row["finding_id"] for row in minimized})
    rows = []
    for item, safe_item in zip(risk["findings"], minimized):
        rows.append({"finding_id": safe_item["finding_id"],
                     **{k: deepcopy(item[k]) for k in IDENTITY_FIELDS},
                     "risk": deepcopy(item["risk"]), "analysis": advice[safe_item["finding_id"]]})
    result = {"schema_version": "1.0", "generated_by": "cloudguard-ai", "analysis_mode": mode,
              "provider": name, "informational_only": True, "trust_rule": TRUST_RULE,
              "advisory_notice": NOTICE, "terraform_examples_advisory": True,
              "deterministic_context": context, "findings": rows}
    validate_remediation(result, risk)
    return result


def validate_remediation(report, risk):
    """Check the built report's schema fields AND bind context to verified inputs."""
    require(set(report) == {"schema_version", "generated_by", "analysis_mode", "provider",
            "informational_only", "trust_rule", "advisory_notice", "terraform_examples_advisory",
            "deterministic_context", "findings"}, "Invalid remediation report fields")
    require(report["schema_version"] == "1.0" and report["generated_by"] == "cloudguard-ai"
            and report["analysis_mode"] in ("offline", "ai") and report["informational_only"] is True
            and report["terraform_examples_advisory"] is True
            and report["trust_rule"] == TRUST_RULE and report["advisory_notice"] == NOTICE,
            "Invalid advisory report authority fields")
    require(isinstance(report["provider"], str)
            and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", report["provider"]) is not None,
            "Invalid provider identifier")
    require(serialize(report["deterministic_context"]) == serialize(deterministic_context(risk)),
            "Deterministic context was changed")
    require(isinstance(report["findings"], list) and len(report["findings"]) == len(risk["findings"]),
            "Advisory report dropped findings")
    for index, (row, original) in enumerate(zip(report["findings"], risk["findings"]), 1):
        expected = {"finding_id": f"finding-{index:06d}", **{k: original[k] for k in IDENTITY_FIELDS}, "risk": original["risk"]}
        require(isinstance(row, dict) and set(row) == {*expected, "analysis"}, "Invalid remediation finding fields")
        require(serialize({k: row[k] for k in expected}) == serialize(expected), "Deterministic finding was changed")
        validate_analysis(row["analysis"])


def render_markdown(report):
    """Render data in inert text fences; never trust source/provider Markdown."""
    def block(value):
        text = json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True)
        longest = max((len(m[0]) for m in re.finditer(r"`+", text)), default=0)
        fence = "`" * max(3, longest + 1)
        return fence + "text\n" + text + "\n" + fence + "\n"
    lines = ["# CloudGuard-AI Advisory Security Analysis", "", TRUST_RULE, "", NOTICE, "",
             "Mode: " + report["analysis_mode"], "", "## Deterministic context", "",
             block(report["deterministic_context"])]
    for row in report["findings"]:
        lines += ["## " + row["finding_id"], "", "Deterministic finding (unchanged):", "",
                  block({k: row[k] for k in ("source", "control_id", "resource", "status", "severity", "exception", "risk")}),
                  "Advisory analysis; Terraform examples are suggestions only:", "", block(row["analysis"])]
    return "\n".join(lines) + "\n"
