package armo_builtins

deny[msga] {
	wl := input[_]
	workload_types := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Pod"}
	workload_types[wl.kind]
	is_kubeflow_dashboard(wl)

	service := input[_]
	service.kind == "Service"
	service.spec.type == "LoadBalancer"
	service.metadata.namespace == wl.metadata.namespace
	wl_connectedto_service(wl, service)

	has_external_address(service)
	not is_internal_load_balancer(service)
	not is_source_restricted(service)

	msga := {
		"alertMessage": sprintf("Kubeflow dashboard %v/%v is exposed to the internet by LoadBalancer service: %v", [wl.metadata.namespace, wl.metadata.name, service.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 6,
		"reviewPaths": ["spec.type"],
		"failedPaths": ["spec.type"],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [service]},
	}
}

is_kubeflow_dashboard(wl) {
	contains(wl.metadata.name, "centraldashboard")
}

is_kubeflow_dashboard(wl) {
	wl.metadata.labels.app == "centraldashboard"
}

is_kubeflow_dashboard(wl) {
	wl.metadata.labels["app.kubernetes.io/name"] == "centraldashboard"
}

wl_connectedto_service(wl, service) {
	count({x | service.spec.selector[x] == wl.metadata.labels[x]}) == count(service.spec.selector)
}

wl_connectedto_service(wl, service) {
	wl.spec.selector.matchLabels == service.spec.selector
}

has_external_address(service) {
	service.status.loadBalancer.ingress[_].ip
}

has_external_address(service) {
	service.status.loadBalancer.ingress[_].hostname
}

is_internal_load_balancer(service) {
	internal_load_balancer_annotations := {
		"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal",
		"service.beta.kubernetes.io/azure-load-balancer-internal": "true",
		"networking.gke.io/load-balancer-type": "internal",
		"cloud.google.com/load-balancer-type": "internal",
		"service.beta.kubernetes.io/oci-load-balancer-internal": "true",
		"oci-network-load-balancer.oraclecloud.com/internal": "true",
		"service.beta.kubernetes.io/alibaba-cloud-loadbalancer-address-type": "intranet",
	}
	value := service.metadata.annotations[key]
	lower(value) == internal_load_balancer_annotations[key]
}

# The in-tree AWS cloud provider treats any value other than "false" as internal
is_internal_load_balancer(service) {
	value := service.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-internal"]
	lower(value) != "false"
}

# The AWS Load Balancer Controller provisions internal NLBs unless the scheme is explicitly internet-facing
is_internal_load_balancer(service) {
	is_aws_load_balancer_controller_managed(service)
	not is_aws_internet_facing_scheme(service)
}

is_aws_load_balancer_controller_managed(service) {
	service.spec.loadBalancerClass == "service.k8s.aws/nlb"
}

is_aws_load_balancer_controller_managed(service) {
	aws_controller_types := {"external", "nlb-ip"}
	aws_controller_types[lower(service.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-type"])]
}

is_aws_internet_facing_scheme(service) {
	lower(service.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-scheme"]) == "internet-facing"
}

is_source_restricted(service) {
	count(service.spec.loadBalancerSourceRanges) > 0
	not allows_any_source(service)
}

allows_any_source(service) {
	any_source_ranges := {"0.0.0.0/0", "::/0"}
	any_source_ranges[service.spec.loadBalancerSourceRanges[_]]
}
