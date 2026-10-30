"""Run the complete offline Phase 3 reporting chain from existing scanner JSON."""
import argparse
from pathlib import Path
import sys
from cloudguard.integration import publish
from cloudguard.risk import MODEL_PATH, load_model, read_document
from cloudguard.runtime import ROOT


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkov", type=Path, action="append", default=[])
    parser.add_argument("--conftest", type=Path, action="append", default=[])
    parser.add_argument("--mode", choices=("offline",), default="offline")
    parser.add_argument("--risk-model", type=Path, default=MODEL_PATH)
    parser.add_argument("--current-evidence", action="store_true")
    parser.add_argument("--private-output", type=Path, default=ROOT / "reports/private/phase35")
    parser.add_argument("--sanitized-output", type=Path, default=ROOT / "reports/sanitized/phase35")
    args = parser.parse_args(argv)
    if not (args.checkov or args.conftest):
        parser.error("provide at least one scanner input")
    try:
        inputs = [(source, read_document(path)) for source in ("checkov", "conftest")
                  for path in getattr(args, source)]
        publish(inputs, args.private_output, args.sanitized_output,
                model=load_model(args.risk_model), evidence=args.current_evidence)
    except Exception:
        # Provider/schema/I/O exceptions can contain private values: never echo.
        print("Phase 3 integration failed: input, schema, integrity, dependency or output error. No completed run published.", file=sys.stderr)
        return 2
    print("Phase 3 reporting completed; policy gate conclusions remain independent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
