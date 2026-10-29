"""Render bounded sanitized PR reports locally; never publish or execute gates."""
import argparse
from pathlib import Path
import sys
from cloudguard.pr_evidence import current_policy
from cloudguard.pr_reporting import ReportingError, summarize, write_outputs
from cloudguard.risk import MODEL_PATH, RiskInputError, load_model, read_document
from cloudguard.runtime import ROOT


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--risk", type=Path, required=True)
    parser.add_argument("--remediation", type=Path, help="Optional matching advisory report; absent means NOT_RUN")
    parser.add_argument("--risk-model", type=Path, default=MODEL_PATH)
    parser.add_argument("--current-evidence", action="store_true", help="Read current local Phase 2 records; otherwise gates are UNKNOWN")
    parser.add_argument("--output", type=Path, default=ROOT / "reports/sanitized/pr-summary.json")
    parser.add_argument("--markdown", type=Path, help="Optional new sanitized Markdown file")
    args = parser.parse_args(argv)
    try:
        normalized, risk = read_document(args.findings), read_document(args.risk)
        remediation = read_document(args.remediation) if args.remediation else None
        model = load_model(args.risk_model)
        # Validate all private input before reading matching gate evidence.
        report = summarize(normalized, risk, remediation, model=model)
        if args.current_evidence:
            report["policy"] = current_policy(normalized)
        write_outputs(report, args.output, args.markdown)
    except (ReportingError, RiskInputError, OSError, UnicodeError, RecursionError):
        print("PR reporting failed: invalid/inconsistent input, unavailable evidence I/O or existing/unavailable output. No gate status changed.", file=sys.stderr)
        return 2
    print("Sanitized PR summary generated; CI security gate conclusions unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
