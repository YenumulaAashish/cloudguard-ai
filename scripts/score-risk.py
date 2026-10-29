"""Score a normalized report locally. Risk scoring does not override policy enforcement."""
import argparse
import os
from pathlib import Path
import sys
from cloudguard.findings import serialize
from cloudguard.risk import MODEL_PATH, RiskInputError, assess_risk, load_model, read_document
from cloudguard.runtime import PRIVATE


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Phase 3.1 normalized JSON report")
    parser.add_argument("--output", type=Path, default=PRIVATE / "phase3/risk-report.json",
                        help="New private report file; existing files are never overwritten")
    parser.add_argument("--model", type=Path, default=MODEL_PATH, help="Versioned local risk model JSON")
    args = parser.parse_args(argv)
    created = complete = False
    try:
        report = assess_risk(read_document(args.input), load_model(args.model))
        payload = serialize(report)
        args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
        complete = True
    except RiskInputError as exc:
        print(f"Risk scoring failed: {exc}", file=sys.stderr)
        return 2
    except FileExistsError:
        print("Risk scoring failed: output already exists; choose a new output file.", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, RecursionError):
        print("Risk scoring failed: input/model/output unavailable or too deeply nested.", file=sys.stderr)
        return 2
    finally:
        if created and not complete:
            args.output.unlink(missing_ok=True)
    print(f"Scored {report['summary']['total']} findings; overall priority "
          f"{report['overall']['score']}/100 ({report['overall']['category']}); gate decisions not evaluated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
