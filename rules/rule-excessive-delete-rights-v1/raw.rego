package armo_builtins

import rego.v1

# fails if user can delete important resources
deny contains msga if {
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
	verb in {"delete", "deletecollection", "*"}

	some api_group in rule.apiGroups
	api_group in {"", "*", "apps", "batch"}

	some resource in rule.resources
	resource in {"secrets", "pods", "services", "deployments", "replicasets", "daemonsets", "statefulsets", "jobs", "cronjobs", "*"}

	rule_path := sprintf("relatedObjects[%d].rules[%d]", [i, p])

	verb_path := [sprintf("%s.verbs[%d]", [rule_path, l]) |
		some l
		v := rule.verbs[l]
		v in {"delete", "deletecollection", "*"}
	]

	api_groups_path := [sprintf("%s.apiGroups[%d]", [rule_path, a]) |
		some a
		g := rule.apiGroups[a]
		g in {"", "*", "apps", "batch"}
	]

	resources_path := [sprintf("%s.resources[%d]", [rule_path, r]) |
		some r
		res := rule.resources[r]
		res in {"secrets", "pods", "services", "deployments", "replicasets", "daemonsets", "statefulsets", "jobs", "cronjobs", "*"}
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

# for service accounts
is_same_subjects(subjectVector, subject) if {
	subjectVector.kind == subject.kind
	subjectVector.name == subject.name
	subjectVector.namespace == subject.namespace
}

# for users/groups
is_same_subjects(subjectVector, subject) if {
	subjectVector.kind == subject.kind
	subjectVector.name == subject.name
	subjectVector.apiGroup == subject.apiGroup
}
