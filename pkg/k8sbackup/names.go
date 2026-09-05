package k8sbackup

import (
	"fmt"
	"hash/crc32"
	"regexp"
	"strings"
)

// Archive and blob names inside the PBS snapshots
const (
	ResourcesArchiveName = "resources"
	VolumeArchiveName    = "pvc"
	ManifestBlobName     = "k8s-manifest"
	ManifestFileName     = "k8s-manifest.json"
)

// maxGroupIDLen keeps PBS backup ids comfortably inside their limits
const maxGroupIDLen = 90

var groupIDClean = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

// VolumeGroupID is the PBS backup group id for one PVC: <cluster group>-pvc-<ns>-<name>,
// sanitised and length-capped with a stable hash suffix when truncated.
func VolumeGroupID(clusterBackupID, namespace, pvcName string) string {
	raw := fmt.Sprintf("%s-pvc-%s-%s", clusterBackupID, namespace, pvcName)
	id := groupIDClean.ReplaceAllString(raw, "-")
	if len(id) <= maxGroupIDLen {
		return id
	}
	sum := crc32.ChecksumIEEE([]byte(raw))
	return fmt.Sprintf("%s-%08x", id[:maxGroupIDLen-9], sum)
}

// VolumeGroupPrefix is the prefix shared by every volume group of a cluster
func VolumeGroupPrefix(clusterBackupID string) string { return clusterBackupID + "-pvc-" }

// IsVolumeGroup reports whether a PBS group id belongs to this cluster's volumes
func IsVolumeGroup(clusterBackupID, groupID string) bool {
	return strings.HasPrefix(groupID, VolumeGroupPrefix(clusterBackupID))
}
