"""Normalize existing reports locally; never execute scans or cloud commands."""
import argparse
import json
import os
from pathlib import Path
import sys
from cloudguard.findings import FindingInputError, build_report, serialize
from cloudguard.runtime import PRIVATE


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FindingInputError("Duplicate JSON object keys")
        result[key] = value
    return result


def reject_constant(value):
    raise FindingInputError("Nonstandard JSON number")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkov", type=Path, action="append", default=[], metavar="JSON",
                        help="Complete Checkov Terraform JSON report (repeatable)")
    parser.add_argument("--conftest", type=Path, action="append", default=[], metavar="JSON",
                        help="Conftest test --output json report (repeatable)")
    parser.add_argument("--output", type=Path, default=PRIVATE / "phase3/normalized-findings.json",
                        help="New output file; existing files are never overwritten")
    args = parser.parse_args(argv)
    if not (args.checkov or args.conftest):
        parser.error("provide --checkov and/or --conftest")
    created = complete = False
    try:
        inputs = []
        for source in ("checkov", "conftest"):
            for index, path in enumerate(getattr(args, source), 1):
                try:
                    raw = json.loads(path.read_text(encoding="utf-8-sig"),
                                     object_pairs_hook=unique_object, parse_constant=reject_constant)
                except (OSError, ValueError):
                    raise FindingInputError(f"Cannot read valid JSON from {source} input #{index}") from None
                inputs.append((source, raw))
        report = build_report(inputs)
        payload = serialize(report)
        # Validate/serialize everything before exclusive creation. This also works
        # on filesystems that do not support hard links. Never replace a file.
        args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
        complete = True
    except FindingInputError as exc:
        # Adapter exceptions contain only fixed/value-free validation messages.
        print(f"Normalization failed: {exc}", file=sys.stderr)
        return 2
    except FileExistsError:
        print("Normalization failed: output already exists; choose a new output file.", file=sys.stderr)
        return 2
    except (OSError, UnicodeError):
        print("Normalization failed: output unavailable; choose a writable output file.", file=sys.stderr)
        return 2
    finally:
        if created and not complete:
            args.output.unlink(missing_ok=True)
    print(f"Normalized {report['summary']['total']} findings; reporting only, gate results unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
