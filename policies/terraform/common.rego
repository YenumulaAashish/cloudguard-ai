package main

import rego.v1

changed_addresses contains c.address if {
	some c in object.get(input, "resource_changes", [])
	c.mode == "managed"
}

# Prefer the explicit final change values when a resource has a change record.
resources contains r if {
	some c in object.get(input, "resource_changes", [])
	c.mode == "managed"
	is_object(c.change.after)
	c.change.actions != ["delete"]
	c.change.actions != ["forget"]
	r := {"address": c.address, "mode": c.mode, "type": c.type, "values": c.change.after}
}

# Include unchanged resources and retain the Phase 1 deterministic fixtures.
resources contains r if {
	walk(input.planned_values.root_module, [_, node])
	is_object(node)
	some r in object.get(node, "resources", [])
	r.mode == "managed"
	not r.address in changed_addresses
}

deny contains "INPUT: expected Terraform plan JSON with planned_values.root_module" if {
	not is_object(object.get(object.get(input, "planned_values", {}), "root_module", null))
}

as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)
