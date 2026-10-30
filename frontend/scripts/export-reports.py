"""Explicit, bounded export of four PUBLIC contracts. No private input discovery."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from cloudguard.integration import schema_validate as phase3_schema
from cloudguard.posture import schema_validate as phase4_schema
from cloudguard.pr_reporting import validate_summary

CONTRACTS = {
    'pr': 'pr-summary', 'phase3': 'phase3-evidence',
    'posture': 'cloud-posture-summary', 'phase4': 'phase4-completion',
}


def read_public(folder, filename):
    path = (folder / filename).resolve()
    if not path.is_relative_to((ROOT / 'reports/sanitized').resolve()):
        raise ValueError('Only sanitized report inputs are accepted')
    if path.stat().st_size > 4096:
        raise ValueError('Report exceeds public bound')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate report key')
            result[key] = value
        return result
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique)


def export(phase3, phase4):
    pr = read_public(phase3, 'pr-summary.json')
    receipt3 = read_public(phase3, 'phase3-evidence.json')
    posture = read_public(phase4, 'posture-summary.json')
    receipt4 = read_public(phase4, 'phase4-completion.json')
    phase3_schema(pr, 'summary'); validate_summary(pr)
    phase3_schema(receipt3, 'manifest')
    phase4_schema(posture, 'summary'); phase4_schema(receipt4, 'completion')
    if pr['advisory']['mode'] != receipt3['advisory_mode']:
        raise ValueError('Inconsistent advisory receipt')
    if pr['policy']['opa_conftest'] != 'UNKNOWN':
        raise ValueError('Offline export cannot attest real-plan policy')
    return {'version': '1.0', 'source': 'OFFLINE_SYNTHETIC', 'pr': pr,
            'phase3': receipt3, 'posture': posture, 'phase4': receipt4}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase3-dir', type=Path, required=True)
    parser.add_argument('--phase4-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        bundle = export(args.phase3_dir, args.phase4_dir)
        schemas = {key: json.loads((ROOT / 'security' / (name + '.schema.json')).read_text())
                   for key, name in CONTRACTS.items()}
        target = ROOT / 'frontend/src/data'
        target.mkdir(parents=True, exist_ok=True)
        # Fixed output filenames; validate everything before updating the reviewed snapshot.
        for name, value in [('demo.json', bundle), ('contracts.json', schemas)]:
            (target / name).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    except Exception:
        print('Export rejected: unavailable, invalid or non-public input. Values withheld.', file=sys.stderr)
        return 2
    print('Public offline snapshot exported. No private content or live provenance included.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
