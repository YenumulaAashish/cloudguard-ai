package main

import rego.v1

ssh_rule contains {"address": r.address, "rule": rule} if {
	some r in resources
	r.type in {"aws_security_group", "aws_default_security_group"}
	some rule in object.get(r.values, "ingress", [])
}

ssh_rule contains {"address": r.address, "rule": r.values} if {
	some r in resources
	r.type == "aws_security_group_rule"
	r.values.type == "ingress"
}

ssh_rule contains {"address": r.address, "rule": r.values} if {
	some r in resources
	r.type == "aws_vpc_security_group_ingress_rule"
}

public(rule) if {
	some cidr in object.get(rule, "cidr_blocks", [])
	cidr == "0.0.0.0/0"
}

public(rule) if {
	some cidr in object.get(rule, "ipv6_cidr_blocks", [])
	cidr == "::/0"
}

public(rule) if object.get(rule, "cidr_ipv4", "") == "0.0.0.0/0"

public(rule) if object.get(rule, "cidr_ipv6", "") == "::/0"

ssh(rule) if object.get(rule, "ip_protocol", object.get(rule, "protocol", "")) in {"-1", -1}

ssh(rule) if {
	object.get(rule, "ip_protocol", object.get(rule, "protocol", "")) in {"tcp", "6", 6}
	rule.from_port <= 22
	rule.to_port >= 22
}

deny contains sprintf("SSH: %s exposes SSH to the world", [item.address]) if {
	some item in ssh_rule
	public(item.rule)
	ssh(item.rule)
}
