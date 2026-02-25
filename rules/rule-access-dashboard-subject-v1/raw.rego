package armo_builtins

# input: regoResponseVectorObject
# fails if a subject that is not dashboard service account is bound to dashboard role/clusterrole

deny[msga] {
	subjectVector := input[_]
	subjectVector.name != "kubernetes-dashboard"

	some j
	rolebinding := subjectVector.relatedObjects[j]
	endswith(rolebinding.kind, "Binding")

	some k
	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	some i
	role := subjectVector.relatedObjects[i]
	endswith(role.kind, "Role")
	role.metadata.name == "kubernetes-dashboard"
	rolebinding.roleRef.name == role.metadata.name

	finalpath := [
		sprintf("relatedObjects[%d].subjects[%d]", [j, k]),
		sprintf("relatedObjects[%d].roleRef.name", [j]),
	]

	msga := {
		"alertMessage": sprintf("Subject: %s-%s is bound to dashboard role/clusterrole", [subjectVector.kind, subjectVector.name]),
		"alertScore": 9,
		"reviewPaths": finalpath,
		"failedPaths": finalpath,
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": subjectVector
		}
	}
}

# for service accounts
is_same_subjects(sv, subject) {
	sv.kind == subject.kind
	sv.name == subject.name
	sv.namespace == subject.namespace
}

# for users/groups
is_same_subjects(sv, subject) {
	sv.kind == subject.kind
	sv.name == subject.name
	sv.apiGroup == subject.apiGroup
}
