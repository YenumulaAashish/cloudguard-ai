package main

import rego.v1

test_tags_present if {
	r := fixture_resource("aws_vpc", {"tags": fixture_tags})
	count(deny) == 0 with input as fixture_plan([r])
}

test_tags_missing if {
	r := fixture_resource("aws_vpc", {"tags": object.remove(fixture_tags, ["Project"])})
	count(deny) == 1 with input as fixture_plan([r])
}

test_tags_provider_defaults_boundary if {
	r := fixture_resource("aws_vpc", {"tags_all": fixture_tags})
	count(deny) == 0 with input as fixture_plan([r])
}

test_tags_blank if {
	r := fixture_resource("aws_vpc", {"tags": object.union(fixture_tags, {"Project": "  "})})
	count(deny) == 1 with input as fixture_plan([r])
}

test_tags_wrong_manager if {
	r := fixture_resource("aws_vpc", {"tags": object.union(fixture_tags, {"ManagedBy": "manual"})})
	count(deny) == 1 with input as fixture_plan([r])
}
