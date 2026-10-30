"""Analyze supplied local plan JSON; never execute Terraform or cloud commands."""
import argparse
import os
from pathlib import Path
import sys
from cloudguard.network import analyze, MAX_BYTES
from cloudguard.risk import read_document
from cloudguard.findings import serialize
from cloudguard.runtime import PRIVATE


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=PRIVATE / "phase4/network-report.json")
    args = parser.parse_args(argv)
    created = complete = False
    try:
        target = args.output.resolve()
        boundary = PRIVATE.resolve()
        if boundary not in target.parents or args.plan.stat().st_size > MAX_BYTES:
            raise ValueError("Invalid boundary or input size")
        report = analyze(read_document(args.plan))
        payload = serialize(report)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
            out.write(payload); out.flush(); os.fsync(out.fileno())
        complete = True
    except Exception:
        print("Network analysis failed: invalid input, schema, dependency or output. Choose a new private output path.", file=sys.stderr)
        return 2
    finally:
        if created and not complete: target.unlink(missing_ok=True)
    print("Network structural analysis complete; effective access is not established.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
