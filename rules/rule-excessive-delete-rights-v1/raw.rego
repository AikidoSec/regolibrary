package armo_builtins

import future.keywords.in

# fails if user can delete important resources
deny[msga] {
	some subjectVector in input

	# High-selectivity pruning first: binding + matching subject
	some j
	rolebinding := subjectVector.relatedObjects[j]
	endswith(rolebinding.kind, "Binding")

	some k
	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	# Enforce RBAC linkage: binding must reference the matched role
	some i
	role := subjectVector.relatedObjects[i]
	endswith(role.kind, "Role")
	role.metadata.name == rolebinding.roleRef.name

	some p
	rule := role.rules[p]

	some verb in rule.verbs
	is_delete_verb(verb)

	some api_group in rule.apiGroups
	is_target_api_group(api_group)

	some resource in rule.resources
	is_important_resource(resource)

	rule_path := sprintf("relatedObjects[%d].rules[%d]", [i, p])

	verb_path := [sprintf("%s.verbs[%d]", [rule_path, l]) |
		some l
		v := rule.verbs[l]
		is_delete_verb(v)
	]

	api_groups_path := [sprintf("%s.apiGroups[%d]", [rule_path, a]) |
		some a
		g := rule.apiGroups[a]
		is_target_api_group(g)
	]

	resources_path := [sprintf("%s.resources[%d]", [rule_path, r]) |
		some r
		res := rule.resources[r]
		is_important_resource(res)
	]

	finalpath := array.concat(
		array.concat(resources_path, verb_path),
		array.concat(api_groups_path, [
			sprintf("relatedObjects[%d].subjects[%d]", [j, k]),
			sprintf("relatedObjects[%d].roleRef.name", [j]),
		]),
	)

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can delete important resources", [subjectVector.kind, subjectVector.name]),
		"alertScore": 3,
		"fixPaths": [],
		"reviewPaths": finalpath,
		"failedPaths": finalpath,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": subjectVector,
		},
	}
}

is_delete_verb(v) { v == "delete" }
is_delete_verb(v) { v == "deletecollection" }
is_delete_verb(v) { v == "*" }

is_target_api_group(g) { g == "" }
is_target_api_group(g) { g == "*" }
is_target_api_group(g) { g == "apps" }
is_target_api_group(g) { g == "batch" }

is_important_resource(r) { r == "secrets" }
is_important_resource(r) { r == "pods" }
is_important_resource(r) { r == "services" }
is_important_resource(r) { r == "deployments" }
is_important_resource(r) { r == "replicasets" }
is_important_resource(r) { r == "daemonsets" }
is_important_resource(r) { r == "statefulsets" }
is_important_resource(r) { r == "jobs" }
is_important_resource(r) { r == "cronjobs" }
is_important_resource(r) { r == "*" }

# for service accounts
is_same_subjects(subjectVector, subject) {
	subjectVector.kind == subject.kind
	subjectVector.name == subject.name
	subjectVector.namespace == subject.namespace
}

# for users/groups
is_same_subjects(subjectVector, subject) {
	subjectVector.kind == subject.kind
	subjectVector.name == subject.name
	subjectVector.apiGroup == subject.apiGroup
}
