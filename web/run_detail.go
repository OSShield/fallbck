package web

import (
	"encoding/json"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/k8sbackup"
	"github.com/osshield/fallbck/pkg/rundetail"
)

func prettyJSON(value any) string {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "Details could not be decoded."
	}
	return string(b)
}
func runDetailData(run *db.BackupRun) map[string]any {
	data := map[string]any{"Run": run, "Polling": run.Status.IsActive() || run.Status == db.RunStatusCancelling}
	var progress rundetail.Progress
	if json.Unmarshal(run.Progress, &progress) == nil {
		data["Progress"] = progress
	}
	var wrapper rundetail.Wrapper
	if len(run.Details) == 0 {
		return data
	}
	if err := json.Unmarshal(run.Details, &wrapper); err != nil {
		data["DetailsError"] = "This run contains malformed detail data. Download the record for inspection."
		return data
	}
	switch wrapper.Type {
	case rundetail.TypeFilesystem:
		var details rundetail.Filesystem
		if json.Unmarshal(run.Details, &details) == nil {
			data["Filesystem"] = details
		}
	case rundetail.TypeDatabase:
		var manifest dbbackup.Manifest
		if json.Unmarshal(wrapper.Manifest, &manifest) == nil {
			data["Database"] = manifest
		}
	case rundetail.TypeKubernetes:
		var manifest k8sbackup.Manifest
		if json.Unmarshal(wrapper.Manifest, &manifest) == nil {
			data["Kubernetes"] = manifest
		}
	}
	var raw any
	if json.Unmarshal(run.Details, &raw) == nil {
		data["RawDetails"] = raw
	}
	return data
}
