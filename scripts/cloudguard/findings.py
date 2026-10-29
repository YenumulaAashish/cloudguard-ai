"""Deterministic reporting adapters; never execute or approve a security gate."""
import json
import re
from .exceptions import REVIEWED, terraform_report

SCHEMA_VERSION = "1.0"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")
STATUSES = ("failed", "warning", "skipped")


class FindingInputError(ValueError):
    """Invalid/unsupported source output, with a value-free public message."""


def optional_text(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise FindingInputError("Expected a string or null")
    return value or None


def severity(value):
    value = optional_text(value)
    normalized = value.strip().upper() if value else "UNKNOWN"
    return normalized if normalized in SEVERITIES else "UNKNOWN"


def count(value):
    if type(value) is not int or value < 0:
        raise FindingInputError("Expected a nonnegative integer count")
    return value


def finding(source, control_id, resource, status, level=None, message=None,
            file=None, line=None, line_end=None, exception=False, metadata=None):
    return {"schema_version": SCHEMA_VERSION, "source": source,
            "control_id": control_id, "resource": resource, "status": status,
            "severity": severity(level), "message": message, "file": file,
            "line": line, "line_end": line_end, "exception": exception,
            "metadata": metadata or {}}


def normalize_checkov(raw):
    """Accept the complete terraform source report emitted by security-scan.py."""
    try:
        report = terraform_report(raw)
        results, summary = report["results"], report["summary"]
        if not isinstance(results, dict) or not isinstance(summary, dict):
            raise FindingInputError("Invalid Checkov report objects")
        if count(summary["parsing_errors"]) or results.get("parsing_errors"):
            raise FindingInputError("Checkov contains parsing errors; no report generated")
        output = []
        for group, status, key in (("passed_checks", "passed", "passed"),
                                   ("failed_checks", "failed", "failed"),
                                   ("skipped_checks", "skipped", "skipped")):
            records = results[group]
            if not isinstance(records, list) or count(summary[key]) != len(records):
                raise FindingInputError("Incomplete Checkov result groups or counts")
            for record in records:
                if not isinstance(record, dict):
                    raise FindingInputError("Invalid Checkov result record")
                control = optional_text(record["check_id"])
                resource = optional_text(record.get("resource"))
                if not control or record["check_result"]["result"] != status.upper():
                    raise FindingInputError("Missing Checkov control ID or inconsistent status")
                if status == "passed":
                    continue
                start = end = None
                lines = record.get("file_line_range")
                if lines not in (None, []):
                    if (not isinstance(lines, list) or len(lines) != 2
                            or any(type(n) is not int or n < 1 for n in lines)
                            or lines[1] < lines[0]):
                        raise FindingInputError("Invalid Checkov line range")
                    start, end = lines
                output.append(finding(
                    "checkov", control, resource, status, record.get("severity"),
                    optional_text(record.get("check_name")),
                    optional_text(record.get("file_path")), start, end,
                    exception=status == "skipped" and (control, resource) in REVIEWED))
        return output
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        if isinstance(exc, FindingInputError):
            raise
        raise FindingInputError("Invalid or unsupported Checkov Terraform report") from None


# These are identifiers already present in the repository's Rego deny messages,
# not new detection rules or severity assignments. Unknown messages stay intact
# but do not acquire invented resource/control identifiers.
POLICY_PATTERNS = {
    "SSH": r"(.+) exposes SSH to the world",
    "S3_PUBLIC": r"(.+) (?:requires all four public access blocks|enables a public ACL)",
    "S3_ENCRYPTION": r"(.+) requires explicit known encryption",
    "IAM": r"(.+) (?:has unknown or invalid policy JSON|allows wildcard actions|uses Allow with NotAction)",
    "TAGS": r"(.+) (?:missing (?:Project|Environment|ManagedBy)|ManagedBy must be Terraform)",
    "UNKNOWN": r"(.+) (?:has unresolved security field [A-Za-z_][A-Za-z0-9_]*|final resource values are unresolved)",
}
ADDRESS_PART = r'[A-Za-z_][A-Za-z0-9_-]*(?:\[(?:[0-9]+|"(?:[^"\\]|\\.)*")\])?'
ADDRESS = re.compile(ADDRESS_PART + r"(?:\." + ADDRESS_PART + r")+")


def policy_identity(message, query):
    if message:
        prefix, separator, body = message.partition(": ")
        if separator and prefix in (*POLICY_PATTERNS, "INPUT"):
            pattern = POLICY_PATTERNS.get(prefix)
            match = re.fullmatch(pattern, body) if pattern else None
            resource = match[1] if match and ADDRESS.fullmatch(match[1]) else None
            return prefix, resource
    return query, None


def normalize_conftest(raw):
    """Adapt conftest test --output json, not opa test's unit-test results."""
    if not isinstance(raw, list) or not raw:
        raise FindingInputError("Expected a nonempty Conftest result array")
    output = []
    for row in raw:
        if not isinstance(row, dict) or "filename" not in row or "namespace" not in row:
            raise FindingInputError("Expected a Conftest input/namespace result")
        filename = optional_text(row["filename"])
        namespace = optional_text(row["namespace"])
        count(row.get("successes"))
        if row.get("exception") or row.get("exceptions") or row.get("error") or row.get("errors"):
            raise FindingInputError("Conftest errors/exceptions are unsupported; policies define no exemptions")
        for group, status in (("failures", "failed"), ("warnings", "warning")):
            records = row.get(group, [])
            if not isinstance(records, list):
                raise FindingInputError("Invalid Conftest result group")
            for record in records:
                if not isinstance(record, dict) or "msg" not in record:
                    raise FindingInputError("Invalid Conftest diagnostic")
                message = optional_text(record["msg"])
                metadata = record.get("metadata")
                if metadata is None:
                    metadata = {}
                if not isinstance(metadata, dict):
                    raise FindingInputError("Invalid Conftest metadata")
                query = optional_text(metadata.get("query"))
                control, resource = policy_identity(message, query)
                # The filename is the tested JSON input, not a Terraform source file.
                output.append(finding(
                    "conftest", control, resource, status, message=message,
                    metadata={"input_file": filename, "namespace": namespace, "query": query}))
    return output


def build_report(inputs):
    """Stable order and bytes; preserve distinct diagnostics and duplicates."""
    findings, sources = [], set()
    adapters = {"checkov": normalize_checkov, "conftest": normalize_conftest}
    for source, raw in inputs:
        if source not in adapters:
            raise FindingInputError("Unsupported finding source")
        sources.add(source)
        findings.extend(adapters[source](raw))
    if not sources:
        raise FindingInputError("At least one source input is required")
    findings.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=True))
    summary = {"total": len(findings),
               **{level.lower(): sum(f["severity"] == level for f in findings) for level in SEVERITIES},
               **{status: sum(f["status"] == status for f in findings) for status in STATUSES}}
    return {"schema_version": SCHEMA_VERSION, "generated_by": "cloudguard-ai",
            "sources": sorted(sources), "summary": summary, "findings": findings}


def serialize(report):
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
