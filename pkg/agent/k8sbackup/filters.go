package k8sbackup

import (
	"path"
	"strings"
)

// defaultExcludedResources are group/resource pairs never worth backing up: runtime
// churn, controller-regenerated objects and virtual review APIs. Secrets are handled
// separately (resources.include_secrets).
var defaultExcludedResources = []string{
	"/events",
	"events.k8s.io/events",
	"/endpoints",
	"discovery.k8s.io/endpointslices",
	"coordination.k8s.io/leases",
	"/componentstatuses",
	"metrics.k8s.io/*",
	"custom.metrics.k8s.io/*",
	"external.metrics.k8s.io/*",
	"authorization.k8s.io/*",
	"authentication.k8s.io/*",
}

// resourceKey renders group/resource ("" group = core, rendered as "/pods")
func resourceKey(group, resource string) string { return group + "/" + resource }

// matchResource matches "group/resource" patterns; "*" wildcards either side,
// path.Match globs within each side. The core group is the empty string ("/secrets"
// or "*/secrets" both match core secrets).
func matchResource(pattern, group, resource string) bool {
	pg, pr, ok := strings.Cut(pattern, "/")
	if !ok {
		return false
	}
	side := func(p, v string) bool {
		if p == "*" {
			return true
		}
		if ok, _ := path.Match(p, v); ok {
			return true
		}
		return p == v
	}
	return side(pg, group) && side(pr, resource)
}

// excludedResource decides whether a resource type is skipped by the dump
func excludedResource(group, resource string, extra []string, includeSecrets bool) bool {
	if group == "" && resource == "secrets" && !includeSecrets {
		return true
	}
	for _, p := range defaultExcludedResources {
		if matchResource(p, group, resource) {
			return true
		}
	}
	for _, p := range extra {
		if matchResource(p, group, resource) {
			return true
		}
	}
	return false
}
