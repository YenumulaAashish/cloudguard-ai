package main

import rego.v1

tagged_types := {
	"aws_vpc", "aws_subnet", "aws_internet_gateway", "aws_route_table",
	"aws_security_group", "aws_default_security_group", "aws_vpc_security_group_ingress_rule",
	"aws_s3_bucket", "aws_iam_role", "aws_iam_policy", "aws_instance",
}

required_tags := {"Project", "Environment", "ManagedBy"}

valid_tag(tags, key) if {
	is_string(tags[key])
	trim_space(tags[key]) != ""
}

deny contains sprintf("TAGS: %s missing %s", [r.address, key]) if {
	some r in resources
	r.type in tagged_types
	tags := object.get(r.values, "tags_all", object.get(r.values, "tags", {}))
	some key in required_tags
	not valid_tag(tags, key)
}

deny contains sprintf("TAGS: %s ManagedBy must be Terraform", [r.address]) if {
	some r in resources
	r.type in tagged_types
	tags := object.get(r.values, "tags_all", object.get(r.values, "tags", {}))
	object.get(tags, "ManagedBy", "") != "Terraform"
}
