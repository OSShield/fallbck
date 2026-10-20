//go:build pbse2e

package tokencheck

import (
	"context"
	"os"
	"testing"

	"github.com/osshield/fallbck/pkg/pbs"
	"github.com/osshield/fallbck/pkg/pbse2e"
)

var srv *pbse2e.PBS

func TestMain(m *testing.M) { os.Exit(pbse2e.Main(m, &srv)) }

// TestTokenCheckRealPBS widens and narrows the ACLs of check@pbs and its token on a
// real PBS and asserts what the check makes of PBS's /access/permissions answer. A
// token's effective rights are its own ACLs intersected with its user's, so each
// change is applied to both, except where the intersection itself is under test.
func TestTokenCheckRealPBS(t *testing.T) {
	const user, token = "check@pbs", "check@pbs!fallbck"
	target := srv.Target("check", "tokencheck")
	acl := func(path, role string, del bool, ids ...string) {
		t.Helper()
		for _, id := range ids {
			args := []string{"proxmox-backup-manager", "acl", "update", path, role, "--auth-id", id}
			if del {
				args = append(args, "--delete")
			}
			if out, err := srv.Exec(nil, nil, args...); err != nil {
				t.Fatalf("acl update %s %s %s: %v\n%s", path, role, id, err, out)
			}
		}
	}
	expect := func(want string) *pbs.TokenCheck {
		t.Helper()
		res := evaluate(context.Background(), target)
		if res.Status != want {
			t.Fatalf("status %q, want %q (error %q, findings %+v, permissions %v)", res.Status, want, res.Error, res.Findings, res.Permissions)
		}
		return res
	}

	t.Run("DatastoreBackup on the namespace is ok", func(t *testing.T) {
		if res := expect(pbs.TokenOK); res.TokenID != token {
			t.Errorf("token id %q", res.TokenID)
		}
	})

	t.Run("DatastoreBackup on the datastore is ok", func(t *testing.T) {
		acl("/datastore/"+pbse2e.Datastore, "DatastoreBackup", false, user, token)
		defer acl("/datastore/"+pbse2e.Datastore, "DatastoreBackup", true, user, token)
		expect(pbs.TokenOK)
	})

	t.Run("Audit on / is excess", func(t *testing.T) {
		acl("/", "Audit", false, user, token)
		defer acl("/", "Audit", true, user, token)
		res := expect(pbs.TokenExcess)
		found := false
		for _, f := range res.Findings {
			found = found || f.Path == "/"
		}
		if !found {
			t.Errorf("no finding on /: %+v", res.Findings)
		}
	})

	t.Run("token outside its namespace is missing", func(t *testing.T) {
		other := *target
		other.Namespace = "e2e"
		if res := evaluate(context.Background(), &other); res.Status != pbs.TokenMissing {
			t.Fatalf("status %q, want missing (error %q)", res.Status, res.Error)
		}
	})

	// Last: the token keeps its own ACL, its user loses DatastoreBackup, so the
	// intersection is empty and PBS must report nothing at the target path
	t.Run("user without the ACL makes the token missing", func(t *testing.T) {
		acl("/datastore/"+pbse2e.Datastore+"/tokencheck", "DatastoreBackup", true, user)
		defer acl("/datastore/"+pbse2e.Datastore+"/tokencheck", "DatastoreBackup", false, user)
		expect(pbs.TokenMissing)
	})
}
