package armo_builtins

# Fails if user can modify all configmaps
deny[msga] {
	subjectVector := input[_]

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
	is_configmap_mutation_verb(verb)

	some la
	apiGroup := rule.apiGroups[la]
	is_core_or_wildcard_group(apiGroup)

	some lr
	resource := rule.resources[lr]
	is_configmap_or_wildcard_resource(resource)

	rule_path := sprintf("relatedObjects[%d].rules[%d]", [i, p])

	verb_path := [sprintf("%s.verbs[%d]", [rule_path, l]) |
		some l
		v := rule.verbs[l]
		is_configmap_mutation_verb(v)
	]

	api_groups_path := [sprintf("%s.apiGroups[%d]", [rule_path, a]) |
		some a
		g := rule.apiGroups[a]
		is_core_or_wildcard_group(g)
	]

	resources_path := [sprintf("%s.resources[%d]", [rule_path, r]) |
		some r
		res := rule.resources[r]
		is_configmap_or_wildcard_resource(res)
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
deny[msga] {
	subjectVector := input[_]

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
	is_configmap_mutation_verb(verb)

	some la
	apiGroup := rule.apiGroups[la]
	is_core_or_wildcard_group(apiGroup)

	some lr
	resource := rule.resources[lr]
	is_configmap_or_wildcard_resource(resource)

	rule_path := sprintf("relatedObjects[%d].rules[%d]", [i, p])

	verb_path := [sprintf("%s.verbs[%d]", [rule_path, l]) |
		some l
		v := rule.verbs[l]
		is_configmap_mutation_verb(v)
	]

	api_groups_path := [sprintf("%s.apiGroups[%d]", [rule_path, a]) |
		some a
		g := rule.apiGroups[a]
		is_core_or_wildcard_group(g)
	]

	resources_path := [sprintf("%s.resources[%d]", [rule_path, r]) |
		some r
		res := rule.resources[r]
		is_configmap_or_wildcard_resource(res)
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
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": subjectVector,
		},
	}
}

is_configmap_mutation_verb(v) { v == "update" }
is_configmap_mutation_verb(v) { v == "patch" }
is_configmap_mutation_verb(v) { v == "*" }

is_core_or_wildcard_group(g) { g == "" }
is_core_or_wildcard_group(g) { g == "*" }

is_configmap_or_wildcard_resource(r) { r == "configmaps" }
is_configmap_or_wildcard_resource(r) { r == "*" }

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
