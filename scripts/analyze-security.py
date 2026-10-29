"""Private advisory analysis. Deterministic tools decide. AI explains."""
import argparse
import os
from pathlib import Path
import sys
from cloudguard.analysis import AnalysisError, analyze_security, render_markdown
from cloudguard.findings import serialize
from cloudguard.risk import MODEL_PATH, RiskInputError, load_model, read_document
from cloudguard.runtime import PRIVATE


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=Path, required=True, help="Phase 3.1 normalized report")
    parser.add_argument("--risk", type=Path, required=True, help="Matching Phase 3.2 risk report")
    parser.add_argument("--risk-model", type=Path, default=MODEL_PATH, help="Model used to verify the supplied risk report")
    parser.add_argument("--mode", choices=("offline", "ai"), default="offline")
    parser.add_argument("--output", type=Path, default=PRIVATE / "phase3/remediation-report.json")
    parser.add_argument("--markdown", type=Path, help="Optional new private Markdown summary")
    args = parser.parse_args(argv)
    created, complete = [], False
    try:
        if args.mode == "ai":
            raise AnalysisError("AI mode requested but no provider is configured; explicitly select offline mode")
        report = analyze_security(read_document(args.findings), read_document(args.risk),
                                  mode=args.mode, model=load_model(args.risk_model))
        outputs = [(args.output, serialize(report))]
        if args.markdown is not None:
            outputs.append((args.markdown, render_markdown(report)))
        if len({path.resolve() for path, _ in outputs}) != len(outputs):
            raise AnalysisError("JSON and Markdown output paths must differ")
        for path, payload in outputs:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(payload)
        complete = True
    except (AnalysisError, RiskInputError) as exc:
        print(f"Advisory analysis failed: {exc}", file=sys.stderr)
        return 2
    except FileExistsError:
        print("Advisory analysis failed: output already exists; choose new output paths.", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, RecursionError):
        print("Advisory analysis failed: input/model/output unavailable or too deeply nested.", file=sys.stderr)
        return 2
    finally:
        if not complete:
            for path in reversed(created):
                path.unlink(missing_ok=True)
    print(f"Produced {len(report['findings'])} advisory entries in {report['analysis_mode']} mode; deterministic results unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
