"""CLI for the source-and-scan exception contract."""
import argparse
from cloudguard.runtime import ROOT, REPORTS, read_json, write_json
from cloudguard.exceptions import verify
from cloudguard.evidence import record

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan", default=str(ROOT / "reports/private/checkov-raw.json"))
    parser.add_argument("--output", default=str(REPORTS / "checkov-exceptions.json"))
    args = parser.parse_args()
    try:
        raw = read_json(args.scan)
    except (OSError, ValueError):
        raw = {}
    report = verify(ROOT, raw)
    record("checkov-exceptions", report)
    if args.output != str(REPORTS / "checkov-exceptions.json"):
        write_json(args.output, report)
    print(f"Exception contract: {report['result']}; expected={report['expected_exceptions']}, observed={report['observed_exceptions']}")
    raise SystemExit(0 if report["result"] == "PASS" else 1)
