package k8sbackup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	spec "github.com/osshield/fallbck/pkg/k8sbackup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	sigyaml "sigs.k8s.io/yaml"
)

const dumpPageSize = 500

// DumpStats summarises a resource dump for the manifest
type DumpStats struct {
	Counts       map[string]int
	Excluded     []string
	FailedGroups []string
	Namespaces   []string
	Warnings     []string
}

// DumpResources writes every selected API resource as YAML under spoolDir:
// cluster/<group>/<version>/<plural>/<name>.yaml and
// namespaces/<ns>/<group>/<version>/<plural>/<name>.yaml. Memory stays flat: objects
// are fetched in pages of 500, written and dropped.
func DumpResources(ctx context.Context, c *Clients, s *spec.Spec, spoolDir string, progress func(phase string)) (*DumpStats, error) {
	if progress == nil {
		progress = func(string) {}
	}
	stats := &DumpStats{Counts: map[string]int{}}

	progress("discovering API resources")
	lists, err := discovery.ServerPreferredResources(c.Discovery)
	if err != nil {
		// Broken aggregated APIs (a dead metrics-server) must not fail the backup
		var groupErr *discovery.ErrGroupDiscoveryFailed
		if ok := discovery.IsGroupDiscoveryFailedError(err); ok && errorsAs(err, &groupErr) {
			for gv := range groupErr.Groups {
				stats.FailedGroups = append(stats.FailedGroups, gv.String())
			}
			sort.Strings(stats.FailedGroups)
		} else {
			return nil, fmt.Errorf("discovering API resources: %w", err)
		}
	}

	// Namespace set
	progress("listing namespaces")
	nsList, err := c.Core.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}
	allowed := map[string]bool{}
	for _, ns := range nsList.Items {
		if s.Namespaces.Matches(ns.Name) {
			allowed[ns.Name] = true
			stats.Namespaces = append(stats.Namespaces, ns.Name)
		}
	}
	sort.Strings(stats.Namespaces)

	includeSecrets := s.IncludeSecrets()
	for _, list := range lists {
		if list == nil {
			continue
		}
		gv, err := schema.ParseGroupVersion(list.GroupVersion)
		if err != nil {
			continue
		}
		for _, res := range list.APIResources {
			if strings.Contains(res.Name, "/") { // subresource
				continue
			}
			if !hasVerbs(res.Verbs, "list", "get") {
				continue
			}
			if excludedResource(gv.Group, res.Name, s.Resources.ExcludeExtra, includeSecrets) {
				stats.Excluded = append(stats.Excluded, resourceKey(gv.Group, res.Name))
				continue
			}
			gvr := gv.WithResource(res.Name)
			progress("dumping " + resourceKey(gv.Group, res.Name))
			n, err := dumpGVR(ctx, c, gvr, res.Namespaced, s, allowed, spoolDir)
			if err != nil {
				// A single broken resource type (e.g. a CRD with a dead conversion
				// webhook) is recorded, not fatal
				stats.Warnings = append(stats.Warnings, fmt.Sprintf("%s: %v", resourceKey(gv.Group, res.Name), err))
				continue
			}
			if n > 0 {
				stats.Counts[resourceKey(gv.Group, res.Name)] = n
			}
		}
	}
	sort.Strings(stats.Excluded)
	return stats, nil
}

func dumpGVR(ctx context.Context, c *Clients, gvr schema.GroupVersionResource, namespaced bool, s *spec.Spec, allowed map[string]bool, spoolDir string) (int, error) {
	written := 0
	opts := metav1.ListOptions{Limit: dumpPageSize, LabelSelector: s.LabelSelector}
	for {
		page, err := c.Dynamic.Resource(gvr).List(ctx, opts)
		if err != nil {
			return written, err
		}
		for i := range page.Items {
			item := &page.Items[i]
			ns := item.GetNamespace()
			if namespaced && !allowed[ns] {
				continue
			}
			if err := writeObject(spoolDir, gvr, ns, item); err != nil {
				return written, err
			}
			written++
		}
		if page.GetContinue() == "" {
			return written, nil
		}
		opts.Continue = page.GetContinue()
	}
}

func writeObject(spoolDir string, gvr schema.GroupVersionResource, ns string, obj *unstructured.Unstructured) error {
	obj.SetManagedFields(nil)
	group := gvr.Group
	if group == "" {
		group = "core"
	}
	var dir string
	if ns != "" {
		dir = filepath.Join(spoolDir, "namespaces", safeName(ns), safeName(group), gvr.Version, safeName(gvr.Resource))
	} else {
		dir = filepath.Join(spoolDir, "cluster", safeName(group), gvr.Version, safeName(gvr.Resource))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := sigyaml.Marshal(obj.Object)
	if err != nil {
		return fmt.Errorf("encoding %s/%s: %w", gvr.Resource, obj.GetName(), err)
	}
	return os.WriteFile(filepath.Join(dir, safeName(obj.GetName())+".yaml"), data, 0o600)
}

// safeName keeps file names path-safe (RBAC names like "system:masters"); the YAML
// content carries the authoritative name.
func safeName(name string) string {
	name = strings.ReplaceAll(name, ":", "_")
	name = strings.ReplaceAll(name, "/", "_")
	if name == "" || name == "." || name == ".." {
		name = "_" + name
	}
	return name
}

func hasVerbs(verbs []string, want ...string) bool {
	for _, w := range want {
		found := false
		for _, v := range verbs {
			if v == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
