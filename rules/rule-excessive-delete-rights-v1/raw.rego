package armo_builtins

import rego.v1

# fails if user can delete important resources
deny contains msga if {
	some subjectVector in input

	# High-selectivity pruning: find roles with excessive delete rights first.
	# In large clusters there are far fewer "dangerous" roles than bindings, so
	# finding the role/rule first prunes the search space before expanding into
	# bindings and subjects.
	some i
	role := subjectVector.relatedObjects[i]
	endswith(role.kind, "Role")

	some p
	rule := role.rules[p]

	some verb in rule.verbs
	verb in {"delete", "deletecollection", "*"}

	some api_group in rule.apiGroups
	api_group in {"", "*", "apps", "batch"}

	some resource in rule.resources
	resource in {"secrets", "pods", "services", "deployments", "replicasets", "daemonsets", "statefulsets", "jobs", "cronjobs", "*"}

	# Enforce RBAC linkage: find a binding that references this role
	some j
	rolebinding := subjectVector.relatedObjects[j]
	endswith(rolebinding.kind, "Binding")
	rolebinding.roleRef.name == role.metadata.name

	# Verify the subjectVector is listed as a subject in this binding
	some k
	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	rule_path := sprintf("relatedObjects[%d].rules[%d]", [i, p])

	verb_path := [sprintf("%s.verbs[%d]", [rule_path, l]) |
		some l
		rule.verbs[l] in {"delete", "deletecollection", "*"}
	]

	api_groups_path := [sprintf("%s.apiGroups[%d]", [rule_path, a]) |
		some a
		rule.apiGroups[a] in {"", "*", "apps", "batch"}
	]

	resources_path := [sprintf("%s.resources[%d]", [rule_path, r]) |
		some r
		rule.resources[r] in {"secrets", "pods", "services", "deployments", "replicasets", "daemonsets", "statefulsets", "jobs", "cronjobs", "*"}
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
