"""Remove only generated plans; never state or arbitrary directories."""
from pathlib import Path
root = Path(__file__).resolve().parents[1]
for name in ("tfplan", "tfplan.json"):
    (root / "terraform" / name).unlink(missing_ok=True)
