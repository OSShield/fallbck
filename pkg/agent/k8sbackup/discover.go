package k8sbackup

import (
	"context"
	"fmt"
	"sort"
	"strings"

	spec "github.com/osshield/fallbck/pkg/k8sbackup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const skipAnnotation = "fallbck.io/skip"
const defaultSnapshotClassAnnotation = "snapshot.storage.kubernetes.io/is-default-class"

// snapshotCRDPresent reports whether the v1 snapshot API is served
func snapshotCRDPresent(c *Clients) bool {
	list, err := c.Discovery.ServerResourcesForGroupVersion("snapshot.storage.k8s.io/v1")
	if err != nil || list == nil {
		return false
	}
	for _, r := range list.APIResources {
		if r.Name == "volumesnapshots" {
			return true
		}
	}
	return false
}

// snapshotClassFor picks the VolumeSnapshotClass for a provisioner: job override →
// default-class annotation → the sole class with a matching driver.
type snapshotClasses struct {
	byDriver map[string][]string // driver -> class names (default first)
}

func loadSnapshotClasses(ctx context.Context, c *Clients) (*snapshotClasses, error) {
	sc := &snapshotClasses{byDriver: map[string][]string{}}
	list, err := c.Dynamic.Resource(snapshotClassGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, item := range list.Items {
		driver, _, _ := unstructuredString(item.Object, "driver")
		if driver == "" {
			continue
		}
		name := item.GetName()
		if item.GetAnnotations()[defaultSnapshotClassAnnotation] == "true" {
			sc.byDriver[driver] = append([]string{name}, sc.byDriver[driver]...)
		} else {
			sc.byDriver[driver] = append(sc.byDriver[driver], name)
		}
	}
	return sc, nil
}

func (s *snapshotClasses) classFor(driver string) string {
	classes := s.byDriver[driver]
	if len(classes) == 0 {
		return ""
	}
	return classes[0] // default-annotated first, else the first (sole sensible pick)
}

func unstructuredString(obj map[string]interface{}, fields ...string) (string, bool, error) {
	cur := obj
	for i, f := range fields {
		v, ok := cur[f]
		if !ok {
			return "", false, nil
		}
		if i == len(fields)-1 {
			s, ok := v.(string)
			return s, ok, nil
		}
		next, ok := v.(map[string]interface{})
		if !ok {
			return "", false, nil
		}
		cur = next
	}
	return "", false, nil
}

// PlanVolumes selects the PVCs a run backs up and decides snapshot vs live per volume
func PlanVolumes(ctx context.Context, c *Clients, s *spec.Spec, clusterBackupID string) ([]spec.VolumePlan, []string, bool, error) {
	var warnings []string
	if s.Volumes.Mode == spec.VolumesNone {
		return nil, nil, false, nil
	}
	crd := snapshotCRDPresent(c)

	var classes *snapshotClasses
	if crd {
		var err error
		if classes, err = loadSnapshotClasses(ctx, c); err != nil {
			warnings = append(warnings, fmt.Sprintf("listing volume snapshot classes: %v", err))
			classes = &snapshotClasses{byDriver: map[string][]string{}}
		}
	} else {
		classes = &snapshotClasses{byDriver: map[string][]string{}}
	}

	// StorageClass -> provisioner (+ cluster default class)
	provisioners := map[string]string{}
	defaultSC := ""
	if scList, err := c.Core.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{}); err == nil {
		for _, sc := range scList.Items {
			provisioners[sc.Name] = sc.Provisioner
			if sc.Annotations["storageclass.kubernetes.io/is-default-class"] == "true" {
				defaultSC = sc.Name
			}
		}
	} else {
		warnings = append(warnings, fmt.Sprintf("listing storage classes: %v", err))
	}

	selector := strings.TrimSpace(s.Volumes.LabelSelector)
	if s.Volumes.Mode == spec.VolumesAll && selector == "" {
		selector = ""
	}
	pvcs, err := c.Core.CoreV1().PersistentVolumeClaims("").List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, warnings, crd, fmt.Errorf("listing persistent volume claims: %w", err)
	}

	nsFilter := s.VolumeNamespaces()
	scAllowed := func(name string) bool {
		if len(s.Volumes.StorageClasses) > 0 {
			ok := false
			for _, want := range s.Volumes.StorageClasses {
				if want == name {
					ok = true
				}
			}
			if !ok {
				return false
			}
		}
		for _, no := range s.Volumes.ExcludeStorageClasses {
			if no == name {
				return false
			}
		}
		return true
	}

	var plans []spec.VolumePlan
	for i := range pvcs.Items {
		pvc := &pvcs.Items[i]
		if !nsFilter.Matches(pvc.Namespace) {
			continue
		}
		if pvc.Annotations[skipAnnotation] == "true" {
			continue
		}
		sc := ""
		if pvc.Spec.StorageClassName != nil {
			sc = *pvc.Spec.StorageClassName
		}
		if sc == "" {
			sc = defaultSC
		}
		if !scAllowed(sc) {
			continue
		}
		plan := spec.VolumePlan{
			Namespace:    pvc.Namespace,
			PVCName:      pvc.Name,
			PVName:       pvc.Spec.VolumeName,
			StorageClass: sc,
			VolumeMode:   string(corev1.PersistentVolumeFilesystem),
			GroupID:      spec.VolumeGroupID(clusterBackupID, pvc.Namespace, pvc.Name),
		}
		if pvc.Spec.VolumeMode != nil {
			plan.VolumeMode = string(*pvc.Spec.VolumeMode)
		}
		if cap, ok := pvc.Status.Capacity[corev1.ResourceStorage]; ok {
			plan.CapacityBytes = cap.Value()
		}
		plan.Provisioner = provisioners[sc]
		if plan.Provisioner == "" {
			plan.Provisioner = pvc.Annotations["volume.kubernetes.io/storage-provisioner"]
		}

		switch {
		case pvc.Status.Phase != corev1.ClaimBound:
			plan.Mode = spec.ModeSkipped
			plan.SkipReason = fmt.Sprintf("PVC is %s, not Bound", pvc.Status.Phase)
		case plan.VolumeMode == string(corev1.PersistentVolumeBlock):
			plan.Mode = spec.ModeSkipped
			plan.SkipReason = "volumeMode Block is not supported"
		default:
			snapClass := s.Volumes.SnapshotClassOverrides[sc]
			if snapClass == "" && crd {
				snapClass = classes.classFor(plan.Provisioner)
			}
			switch {
			case snapClass != "":
				plan.Mode = spec.ModeSnapshot
				plan.SnapshotClass = snapClass
			case s.Volumes.EffAllowLiveFallback():
				plan.Mode = spec.ModeLive
			default:
				plan.Mode = spec.ModeSkipped
				plan.SkipReason = "no VolumeSnapshotClass for provisioner " + plan.Provisioner + " and live fallback is disabled"
			}
		}
		plans = append(plans, plan)
	}
	sort.Slice(plans, func(i, j int) bool { return plans[i].GroupID < plans[j].GroupID })
	if len(plans) > spec.MaxVolumes {
		return nil, warnings, crd, fmt.Errorf("%d volumes selected, more than the limit of %d; narrow the volume filters", len(plans), spec.MaxVolumes)
	}
	return plans, warnings, crd, nil
}
