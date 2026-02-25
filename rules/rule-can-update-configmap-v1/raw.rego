package armo_builtins

import rego.v1

# Fails if user can modify all configmaps
deny contains msga if {
	some subjectVector in input

	some j
	rolebinding := subjectVector.relatedObjects[j]
	endswith(rolebinding.kind, "Binding")

	some k
	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	some i
	role := subjectVector.relatedObjects[i]
	endswith(role.kind, "Role")
	role.metadata.name == rolebinding.roleRef.name

	some p
	rule := role.rules[p]

	not rule.resourceNames

	some lv
	verb := rule.verbs[lv]
	verb in {"update", "patch", "*"}

	some la
	apiGroup := rule.apiGroups[la]
	apiGroup in {"", "*"}

	some lr
	resource := rule.resources[lr]
	resource in {"configmaps", "*"}

	rule_path := sprintf("relatedObjects[%d].rules[%d]", [i, p])

	verb_path := [sprintf("%s.verbs[%d]", [rule_path, l]) |
		some l
		v := rule.verbs[l]
		v in {"update", "patch", "*"}
	]

	api_groups_path := [sprintf("%s.apiGroups[%d]", [rule_path, a]) |
		some a
		g := rule.apiGroups[a]
		g in {"", "*"}
	]

	resources_path := [sprintf("%s.resources[%d]", [rule_path, r]) |
		some r
		res := rule.resources[r]
		res in {"configmaps", "*"}
	]

	finalpath := array.concat(
		array.concat(resources_path, verb_path),
		array.concat(api_groups_path, [
			sprintf("relatedObjects[%d].subjects[%d]", [j, k]),
			sprintf("relatedObjects[%d].roleRef.name", [j]),
		]),
	)

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can modify 'coredns' configmap", [subjectVector.kind, subjectVector.name]),
		"alertScore": 3,
		"reviewPaths": finalpath,
		"failedPaths": finalpath,
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": subjectVector,
		},
	}
}

# Fails if user can modify the 'coredns' configmap (default for coredns)
deny contains msga if {
	some subjectVector in input

	some j
	rolebinding := subjectVector.relatedObjects[j]
	endswith(rolebinding.kind, "Binding")

	some k
	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	some i
	role := subjectVector.relatedObjects[i]
	endswith(role.kind, "Role")
	role.metadata.name == rolebinding.roleRef.name

	some p
	rule := role.rules[p]

	some rn
	rule.resourceNames[rn] == "coredns"

	some lv
	verb := rule.verbs[lv]
	verb in {"update", "patch", "*"}

	some la
	apiGroup := rule.apiGroups[la]
	apiGroup in {"", "*"}

	some lr
	resource := rule.resources[lr]
	resource in {"configmaps", "*"}

	rule_path := sprintf("relatedObjects[%d].rules[%d]", [i, p])

	verb_path := [sprintf("%s.verbs[%d]", [rule_path, l]) |
		some l
		v := rule.verbs[l]
		v in {"update", "patch", "*"}
	]

	api_groups_path := [sprintf("%s.apiGroups[%d]", [rule_path, a]) |
		some a
		g := rule.apiGroups[a]
		g in {"", "*"}
	]

	resources_path := [sprintf("%s.resources[%d]", [rule_path, r]) |
		some r
		res := rule.resources[r]
		res in {"configmaps", "*"}
	]

	finalpath := array.concat(
		array.concat(resources_path, verb_path),
		array.concat(api_groups_path, [
			sprintf("relatedObjects[%d].subjects[%d]", [j, k]),
			sprintf("relatedObjects[%d].roleRef.name", [j]),
		]),
	)

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can modify 'coredns' configmap", [subjectVector.kind, subjectVector.name]),
		"alertScore": 3,
		"reviewPaths": finalpath,
		"failedPaths": finalpath,
		"fixPaths": [],
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
