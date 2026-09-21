package main

import rego.v1

change_fixture(r, actions, after, unknown) := {
	"address": r.address, "mode": r.mode, "type": r.type,
	"change": {"before": r.values, "after": after, "actions": actions, "after_unknown": unknown},
}

plan_changes(rs, changes) := object.union(fixture_plan(rs), {"resource_changes": changes})

test_plan_updated_ssh_evaluates_after if {
	r := fixture_sg({"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]})
	bad := {"tags": fixture_tags, "ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]}
	count(deny) == 1 with input as plan_changes([r], [change_fixture(r, ["update"], bad, {})])
}

test_plan_deleted_unsafe_resource_excluded if {
	r := fixture_iam("Allow", "*")
	count(deny) == 0 with input as plan_changes([r], [change_fixture(r, ["delete"], null, {})])
}

test_plan_replacement_checked if {
	r := fixture_iam("Allow", "*")
	count(deny) == 1 with input as plan_changes([], [change_fixture(r, ["delete", "create"], r.values, {})])
}

test_plan_unknown_ingress_blocks if {
	r := fixture_resource("aws_security_group", {"tags": fixture_tags})
	count(deny) == 1 with input as plan_changes([], [change_fixture(r, ["create"], r.values, {"ingress": true})])
}

test_plan_unknown_id_allowed if {
	r := fixture_resource("aws_vpc", {"tags": fixture_tags})
	count(deny) == 0 with input as plan_changes([], [change_fixture(r, ["create"], r.values, {"id": true})])
}

test_plan_sensitive_known_iam_checked if {
	r := fixture_iam("Allow", "*")
	c := change_fixture(r, ["create"], r.values, {})
	sensitive := object.union(c, {"change": object.union(c.change, {"after_sensitive": {"policy": true}})})
	count(deny) == 1 with input as plan_changes([], [sensitive])
}

test_plan_noop_unsafe_resource_checked if {
	r := fixture_iam("Allow", "*")
	count(deny) == 1 with input as plan_changes([], [change_fixture(r, ["no-op"], r.values, {})])
}

test_plan_unknown_tags_block if {
	r := fixture_resource("aws_vpc", {"tags": fixture_tags})
	count(deny) == 1 with input as plan_changes([], [change_fixture(r, ["create"], r.values, {"tags_all": {"Project": true}})])
}

test_plan_unknown_legacy_acl_with_known_blocks if {
	c := change_fixture(fixture_bucket, ["create"], fixture_bucket.values, {"acl": true})
	count(deny) == 0 with input as plan_changes([fixture_block(true), fixture_encryption("AES256")], [c])
}

test_plan_unknown_legacy_acl_without_blocks if {
	c := change_fixture(fixture_bucket, ["create"], fixture_bucket.values, {"acl": true})
	count(deny) > 0 with input as plan_changes([fixture_encryption("AES256")], [c])
}

test_plan_whole_unknown_resource_blocks if {
	r := fixture_resource("aws_security_group", {"tags": fixture_tags})
	count(deny) == 1 with input as plan_changes([], [change_fixture(r, ["create"], null, true)])
}
