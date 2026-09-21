package main

import rego.v1

test_network_trusted if {
	r := fixture_sg({"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]})
	count(deny) == 0 with input as fixture_plan([r])
}

test_network_public if {
	r := fixture_sg({"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]})
	count(deny) == 1 with input as fixture_plan([r])
}

test_network_https_boundary if {
	r := fixture_sg({"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]})
	count(deny) == 0 with input as fixture_plan([r])
}

test_network_range if {
	r := fixture_sg({"protocol": "6", "from_port": 0, "to_port": 1024, "cidr_blocks": ["0.0.0.0/0"]})
	count(deny) == 1 with input as fixture_plan([r])
}

test_network_ipv6_all_protocols if {
	r := fixture_resource("aws_vpc_security_group_ingress_rule", {"ip_protocol": "-1", "cidr_ipv6": "::/0", "tags": fixture_tags})
	count(deny) == 1 with input as fixture_plan([r])
}

test_network_egress_excluded if {
	r := fixture_resource("aws_security_group_rule", {"type": "egress", "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]})
	count(deny) == 0 with input as fixture_plan([r])
}
