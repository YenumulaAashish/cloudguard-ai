"""Run source security checks with sanitized evidence."""
from cloudguard.scanning import security_scan
if __name__ == "__main__":
    raise SystemExit(0 if security_scan() else 1)
