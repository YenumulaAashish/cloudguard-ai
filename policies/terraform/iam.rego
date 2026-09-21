package main

import rego.v1

iam_types := {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}

policy_document(value) := json.unmarshal(value) if {
	is_string(value)
	json.is_valid(value)
}

policy_document(value) := value if is_object(value)

valid_policy(value) if {
	doc := policy_document(value)
	is_array(doc.Statement)
}

valid_policy(value) if {
	doc := policy_document(value)
	is_object(doc.Statement)
}

deny contains sprintf("IAM: %s has unknown or invalid policy JSON", [r.address]) if {
	some r in resources
	r.type in iam_types
	not valid_policy(object.get(r.values, "policy", null))
}

deny contains sprintf("IAM: %s allows wildcard actions", [r.address]) if {
	some r in resources
	r.type in iam_types
	doc := policy_document(r.values.policy)
	some statement in as_array(doc.Statement)
	statement.Effect == "Allow"
	some action in as_array(statement.Action)
	contains(action, "*")
}

deny contains sprintf("IAM: %s uses Allow with NotAction", [r.address]) if {
	some r in resources
	r.type in iam_types
	doc := policy_document(r.values.policy)
	some statement in as_array(doc.Statement)
	statement.Effect == "Allow"
	object.get(statement, "NotAction", null) != null
}
