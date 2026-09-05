package pbs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListAndDeleteGroups(t *testing.T) {
	var deleted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api2/json/admin/datastore/store1/groups" {
			t.Errorf("path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got == "" {
			t.Error("missing auth header")
		}
		switch r.Method {
		case http.MethodGet:
			if r.URL.Query().Get("ns") != "prod" {
				t.Errorf("ns param %q", r.URL.Query().Get("ns"))
			}
			w.Write([]byte(`{"data":[{"backup-type":"host","backup-id":"k8s-c1-pvc-app-data","last-backup":1700000000,"backup-count":3}]}`))
		case http.MethodDelete:
			deleted = r.URL.Query().Get("backup-id")
			w.Write([]byte(`{"data":null}`))
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "root@pam!t:s", false, "")
	groups, err := c.ListGroups(context.Background(), "store1", "prod")
	if err != nil || len(groups) != 1 || groups[0].BackupID != "k8s-c1-pvc-app-data" || groups[0].LastBackup != 1700000000 {
		t.Fatalf("ListGroups: %v %+v", err, groups)
	}
	if err := c.DeleteGroup(context.Background(), "store1", "prod", "host", "k8s-c1-pvc-app-data"); err != nil || deleted != "k8s-c1-pvc-app-data" {
		t.Fatalf("DeleteGroup: %v %q", err, deleted)
	}
}
