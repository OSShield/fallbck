package api

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
)

// A ring shared across scopes only names the targets the reader may see, and a ring
// whose keys encrypted runs isn't deleted without force
func TestLiveKeyRingScopeAndDelete(t *testing.T) {
	d := liveDB(t)
	f := seed(t, d)
	ctx := context.Background()

	ring := &db.KeyRing{Name: "shared", Labels: db.Labels{"team": "a"}}
	if err := d.CreateKeyRing(ctx, ring); err != nil {
		t.Fatal(err)
	}
	key := &db.TargetKey{RingID: ring.ID, Fingerprint: "aa:bb"}
	if err := d.CreateTargetKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	for _, tg := range []*db.BackupTarget{f.targetA, f.targetB} {
		if err := d.SetTargetEncryption(ctx, tg.ID, db.EncryptionEncrypt, &ring.ID); err != nil {
			t.Fatal(err)
		}
	}

	op := &auth.Principal{Kind: auth.PrincipalSession, Email: "op@example.com", Bindings: []auth.Binding{
		{Role: auth.RoleOperator, Permissions: auth.BuiltinRoles()[auth.RoleOperator], Selector: db.MustSelector("team=a")},
	}}
	code, body := call(t, liveRouter(d, op), http.MethodGet, "/api/v1/keyrings", nil)
	var rings []db.KeyRing
	if code != http.StatusOK || json.Unmarshal(body, &rings) != nil || len(rings) != 1 {
		t.Fatalf("list: %d %s", code, body)
	}
	if rings[0].TargetCount != 2 || !slices.Equal(rings[0].Targets, []string{"pbs-a"}) {
		t.Errorf("operator sees %d targets named %v, want 2 and [pbs-a]", rings[0].TargetCount, rings[0].Targets)
	}

	admin := liveRouter(d, &auth.Principal{Kind: auth.PrincipalSession, Email: "root@example.com", Bindings: auth.AdminBindings()})
	path := "/api/v1/keyrings/" + ring.ID.String()
	if code, body := call(t, admin, http.MethodDelete, path, nil); code != http.StatusConflict {
		t.Errorf("delete with targets: %d %s", code, body)
	}
	for _, tg := range []*db.BackupTarget{f.targetA, f.targetB} {
		if err := d.SetTargetEncryption(ctx, tg.ID, db.EncryptionNone, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Pool.Exec(ctx, `UPDATE backup_runs SET key_fingerprint = $1 WHERE id = $2`, key.Fingerprint, f.runA.ID); err != nil {
		t.Fatal(err)
	}
	code, body = call(t, admin, http.MethodDelete, path, nil)
	var refused struct{ Runs int }
	if code != http.StatusConflict || json.Unmarshal(body, &refused) != nil || refused.Runs != 1 {
		t.Errorf("delete with encrypted runs: %d %s", code, body)
	}
	if code, body := call(t, admin, http.MethodDelete, path+"?force=true", nil); code != http.StatusOK {
		t.Errorf("forced delete: %d %s", code, body)
	}
}
