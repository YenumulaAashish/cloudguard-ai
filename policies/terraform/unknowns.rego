package main

import rego.v1

# IDs/ARNs computed by AWS are not security decisions. Only policy-relevant
# unknown fields block the plan. Sensitive known values are still evaluated.
security_fields := {
	"aws_security_group": {"ingress"},
	"aws_default_security_group": {"ingress"},
	"aws_security_group_rule": {"type", "protocol", "from_port", "to_port", "cidr_blocks", "ipv6_cidr_blocks"},
	"aws_vpc_security_group_ingress_rule": {"ip_protocol", "from_port", "to_port", "cidr_ipv4", "cidr_ipv6"},
	"aws_s3_bucket": {"bucket", "acl"},
	"aws_s3_bucket_acl": {"acl", "access_control_policy"},
	"aws_s3_bucket_public_access_block": {"bucket", "block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"},
	"aws_s3_bucket_server_side_encryption_configuration": {"bucket", "rule"},
	"aws_iam_policy": {"policy"},
	"aws_iam_role_policy": {"policy"},
	"aws_iam_user_policy": {"policy"},
	"aws_iam_group_policy": {"policy"},
}

unknown_security_field(c, key) if {
	key in object.get(security_fields, c.type, set())
	not blocked_unknown_acl(c, key)
}

# A computed legacy bucket ACL cannot make a bucket public when every planned
# public-access block is explicitly true. Unknown protection still blocks.
blocked_unknown_acl(c, key) if {
	c.type == "aws_s3_bucket"
	key == "acl"
	protected({"values": c.change.after})
}

unknown_security_field(c, key) if {
	c.type in tagged_types
	key in {"tags", "tags_all"}
}

deny contains sprintf("UNKNOWN: %s has unresolved security field %s", [c.address, key]) if {
	some c in object.get(input, "resource_changes", [])
	c.mode == "managed"
	is_object(c.change.after)
	c.change.actions != ["delete"]
	c.change.actions != ["forget"]
	some key, value in object.get(c.change, "after_unknown", {})
	unknown_security_field(c, key)
	walk(value, [_, true])
}

deny contains sprintf("UNKNOWN: %s final resource values are unresolved", [c.address]) if {
	some c in object.get(input, "resource_changes", [])
	c.mode == "managed"
	c.change.actions != ["delete"]
	c.change.actions != ["forget"]
	not is_object(c.change.after)
}

deny contains sprintf("UNKNOWN: %s final resource values are unresolved", [c.address]) if {
	some c in object.get(input, "resource_changes", [])
	c.mode == "managed"
	c.change.actions != ["delete"]
	c.change.actions != ["forget"]
	object.get(c.change, "after_unknown", false) == true
}
