"""Bounded final-state projection shared by local structural analyzers."""
from .findings import serialize
MAX_BYTES = 8 * 1024 * 1024


def require(test):
    if not test:
        raise ValueError("Unsupported, malformed or oversized IAM input")


def project(plan):
    require(isinstance(plan, dict) and plan.get("format_version") in ("1.0", "1.1", "1.2"))
    require(not plan.get("errored") and not plan.get("deferred_changes"))
    require(len(serialize(plan).encode()) <= MAX_BYTES)
    root = plan.get("planned_values", {}).get("root_module")
    require(isinstance(root, dict))
    resources = []
    modules = [0]
    def visit(module, depth=0):
        modules[0] += 1
        require(isinstance(module, dict) and depth <= 32 and modules[0] <= 4096)
        rows, children = module.get("resources", []), module.get("child_modules", [])
        require(isinstance(rows, list) and isinstance(children, list))
        resources.extend(rows); require(len(resources) <= 2048)
        for child in children: visit(child, depth+1)
    visit(root)
    changes = plan.get("resource_changes", [])
    require(isinstance(changes, list) and len(changes) <= 2048)
    by_address = {}
    for row in changes:
        require(isinstance(row, dict) and isinstance(row.get("address"), str) and isinstance(row.get("change"), dict))
        require(row["address"] not in by_address)
        by_address[row["address"]] = row
    # Changes are authoritative for after/after_unknown. Also cover unknown creates
    # omitted from planned_values and omit delete-only objects.
    indexed = {}
    for row in resources:
        require(isinstance(row, dict) and isinstance(row.get("address"), str) and isinstance(row.get("type"), str))
        require(row["address"] not in indexed)
        indexed[row["address"]] = row
    for address, row in by_address.items():
        require(isinstance(row.get("type"), str))
        if address in indexed: require(indexed[address]["type"] == row["type"])
        indexed[address] = {**row, "values": row["change"].get("after")}
    return indexed, by_address
