"""Deterministic private prioritization. Risk scoring does not override policy enforcement."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from .findings import SCHEMA_VERSION, SEVERITIES, STATUSES, serialize
from .runtime import ROOT

MODEL_PATH = ROOT / "security/risk-model.json"
CATEGORIES = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
STATUS_CLASSES = ("failed", "warning", "approved_exception", "unapproved_skip", "passed", "unknown")
FINDING_FIELDS = {"schema_version", "source", "control_id", "resource", "status", "severity",
                  "message", "file", "line", "line_end", "exception", "metadata"}
SOURCES = {"checkov", "conftest"}


class RiskInputError(ValueError):
    """Only fixed, value-free diagnostics may reach CLI stderr."""


def require(condition, message):
    if not condition:
        raise RiskInputError(message)


def integer(value, minimum=0, maximum=None):
    return type(value) is int and value >= minimum and (maximum is None or value <= maximum)


def json_value(value):
    """Reject non-JSON Python objects, non-string keys and nonfinite numbers."""
    def walk(item):
        if isinstance(item, dict):
            require(all(isinstance(k, str) for k in item), "JSON object keys must be strings")
            for child in item.values():
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)
        else:
            require(item is None or type(item) in (str, int, float, bool), "Unsupported JSON value")
    try:
        walk(value)
        json.dumps(value, allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        raise RiskInputError("Input must contain finite JSON values") from None


def read_document(path, label="Input"):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON object keys")
            result[key] = value
        return result

    def reject_constant(value):
        raise RiskInputError("Nonstandard JSON number")

    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"),
                          object_pairs_hook=unique, parse_constant=reject_constant)
    except RiskInputError:
        raise
    except (OSError, ValueError, RecursionError):
        raise RiskInputError(label + " cannot be read as valid JSON") from None


def validate_input(report):
    require(isinstance(report, dict), "Expected a normalized report object")
    require(report.get("schema_version") == SCHEMA_VERSION, "Unsupported normalized schema version")
    require(set(report) == {"schema_version", "generated_by", "sources", "summary", "findings"},
            "Invalid normalized report fields")
    require(report["generated_by"] == "cloudguard-ai", "Unsupported normalized report producer")
    sources = report["sources"]
    require(isinstance(sources, list) and bool(sources)
            and all(isinstance(s, str) and s in SOURCES for s in sources)
            and len(sources) == len(set(sources)), "Invalid normalized sources")
    require(isinstance(report["findings"], list), "Expected a findings array")
    for item in report["findings"]:
        require(isinstance(item, dict) and set(item) == FINDING_FIELDS, "Invalid normalized finding fields")
        require(item["schema_version"] == SCHEMA_VERSION, "Unsupported finding schema version")
        require(isinstance(item["source"], str) and item["source"] in sources, "Invalid finding source")
        require(isinstance(item["severity"], str) and item["severity"] in SEVERITIES, "Invalid normalized severity")
        # Defensive consumer extension: Phase 3.1 emits no passes/unknown status,
        # but a future string is preserved and cannot acquire exception treatment.
        require(isinstance(item["status"], str) and bool(item["status"].strip()), "Invalid finding status")
        require(type(item["exception"]) is bool, "Invalid exception flag")
        for field in ("control_id", "resource", "message", "file"):
            require(item[field] is None or isinstance(item[field], str), "Invalid nullable finding text")
        start, end = item["line"], item["line_end"]
        require((start is None and end is None) or
                (integer(start, 1) and integer(end, 1) and end >= start), "Invalid finding line range")
        require(isinstance(item["metadata"], dict), "Invalid finding metadata")
    json_value(report)
    expected = {"total": len(report["findings"]),
                **{s.lower(): sum(f["severity"] == s for f in report["findings"]) for s in SEVERITIES},
                **{s: sum(f["status"] == s for f in report["findings"]) for s in STATUSES}}
    actual = report["summary"]
    require(isinstance(actual, dict) and set(actual) == set(expected)
            and all(integer(n) for n in actual.values()) and actual == expected,
            "Normalized summary does not match finding records")


def validate_model(model):
    require(isinstance(model, dict) and set(model) == {"risk_model_version", "severity_weights",
            "category_minimums", "status_multipliers", "unknown_status_floor", "control_adjustments"},
            "Invalid risk model fields")
    require(model["risk_model_version"] == "1.0", "Unsupported risk model version")
    weights = model["severity_weights"]
    require(isinstance(weights, dict) and set(weights) == set(SEVERITIES)
            and all(integer(n, 0, 100) for n in weights.values()), "Invalid severity weights")
    ordered = [weights[s] for s in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")]
    require(ordered == sorted(ordered), "Known severity weights must be monotonic")
    thresholds = model["category_minimums"]
    require(isinstance(thresholds, dict) and set(thresholds) == set(CATEGORIES)
            and all(integer(n, 0, 100) for n in thresholds.values()), "Invalid risk thresholds")
    ordered = [thresholds[c] for c in CATEGORIES]
    require(ordered[:2] == [0, 1] and all(a < b for a, b in zip(ordered, ordered[1:])),
            "Risk thresholds must be strictly increasing from NONE=0 and LOW=1")
    ratios = model["status_multipliers"]
    require(isinstance(ratios, dict) and set(ratios) == set(STATUS_CLASSES), "Invalid status rules")
    for status, ratio in ratios.items():
        require(isinstance(ratio, list) and len(ratio) == 2
                and integer(ratio[0]) and integer(ratio[1], 1) and ratio[0] <= ratio[1], "Invalid status multiplier")
        if status in {"failed", "unapproved_skip", "unknown"}:
            require(ratio == [1, 1], "Unresolved findings must retain full prioritization")
        elif status == "passed":
            require(ratio == [0, 1], "Passed findings must have zero prioritization")
        else:
            require(0 < ratio[0] < ratio[1], "Warnings and approved exceptions need a nonzero discount")
    require(integer(model["unknown_status_floor"], 1, 100), "Invalid unknown-status floor")
    adjustments = model["control_adjustments"]
    require(isinstance(adjustments, list), "Invalid control adjustments")
    pairs = set()
    for entry in adjustments:
        require(isinstance(entry, dict) and set(entry) == {"source", "control_id", "category", "value"},
                "Invalid control adjustment fields")
        require(isinstance(entry["source"], str) and entry["source"] in SOURCES
                and isinstance(entry["control_id"], str) and bool(entry["control_id"]), "Invalid adjustment identity")
        require(entry["category"] in ("public_exposure", "iam_privilege", "encryption")
                and integer(entry["value"], 0, 20), "Invalid adjustment category or weight")
        pair = (entry["source"], entry["control_id"])
        require(pair not in pairs, "Duplicate control adjustment")
        pairs.add(pair)
    json_value(model)


def load_model(path=MODEL_PATH):
    model = read_document(path, "Risk model")
    validate_model(model)
    return model


def risk_category(score, model):
    return next(c for c in reversed(CATEGORIES) if score >= model["category_minimums"][c])


def status_class(item):
    if item["status"] == "skipped":
        return "approved_exception" if item["exception"] else "unapproved_skip"
    return item["status"] if item["status"] in {"failed", "warning", "passed"} else "unknown"


def score_finding(item, model, adjustments):
    state = status_class(item)
    base = model["severity_weights"][item["severity"]]
    entry = adjustments.get((item["source"], item["control_id"]))
    adjustment = entry["value"] if entry else 0
    bounded = min(100, max(0, base + adjustment))
    numerator, denominator = model["status_multipliers"][state]
    scaled = (bounded * numerator + denominator - 1) // denominator
    floor = model["unknown_status_floor"] if state == "unknown" else 0
    score = max(scaled, floor)
    conflict = item["exception"] and state != "approved_exception"
    review = (item["severity"] == "UNKNOWN" and state != "passed") or state in {"unknown", "unapproved_skip"} or conflict
    factors = [
        {"name": "base_severity", "value": base,
         "reason": ("UNKNOWN is an explicit provisional review priority, not inferred severity."
                    if item["severity"] == "UNKNOWN" else "Source severity " + item["severity"] + ".")},
        {"name": "control_adjustment", "value": adjustment,
         "reason": ("Exact source/control mapping: " + entry["category"] + "."
                    if entry else "No reviewed adjustment for this source/control pair.")},
        {"name": "bounded_base", "value": bounded, "reason": "Clamp base plus adjustment to 0..100."},
        {"name": "status_multiplier", "value": scaled,
         "reason": f"{state}: ceil(bounded base * {numerator} / {denominator})."},
        {"name": "status_floor", "value": score,
         "reason": f"Unknown status requires priority at least {floor}." if floor else "No additional status floor."},
    ]
    return {**deepcopy(item), "risk": {"score": score, "category": risk_category(score, model),
            "status_class": state, "severity_known": item["severity"] != "UNKNOWN",
            "exception_applied": state == "approved_exception", "exception_conflict": conflict,
            "requires_review": bool(review), "factors": factors}}


def assess_risk(report, model=None):
    """Return a new report; never read/write gate records or mutate caller input."""
    validate_input(report)
    model = load_model() if model is None else model
    validate_model(model)
    adjustments = {(e["source"], e["control_id"]): e for e in model["control_adjustments"]}
    findings = [score_finding(f, model, adjustments) for f in report["findings"]]
    findings.sort(key=serialize)
    summary = {"total": len(findings),
               **{c.lower(): sum(f["risk"]["category"] == c for f in findings) for c in CATEGORIES},
               **{key: sum(f["risk"]["status_class"] == state for f in findings) for state, key in
                  (("failed", "failed"), ("warning", "warning"), ("approved_exception", "approved_exceptions"),
                   ("unapproved_skip", "unapproved_skips"), ("passed", "passed"), ("unknown", "unknown_status"))},
               "unknown_severity": sum(not f["risk"]["severity_known"] for f in findings),
               "requires_review": sum(f["risk"]["requires_review"] for f in findings),
               "exception_conflicts": sum(f["risk"]["exception_conflict"] for f in findings)}
    score = max((f["risk"]["score"] for f in findings), default=0)
    canonical_model = {**model, "control_adjustments": sorted(model["control_adjustments"], key=serialize)}
    return {"schema_version": "1.0", "generated_by": "cloudguard-ai", "input_schema_version": SCHEMA_VERSION,
            "risk_model_version": model["risk_model_version"],
            "risk_model_sha256": hashlib.sha256(serialize(canonical_model).encode("utf-8")).hexdigest(),
            "informational_only": True, "gate_decision": "NOT_EVALUATED",
            "sources": sorted(report["sources"]), "overall": {"score": score,
            "category": risk_category(score, model), "requires_review": summary["requires_review"] > 0},
            "summary": summary, "findings": findings}
