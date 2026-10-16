//go:build m365integration

package m365

// Real-tenant probe: answers the Graph questions the fake cannot (field names, id
// equality between the two mailbox APIs, root folder naming, export sizes). Run with
//
//	FALLBCK_M365_CREDENTIALS=/path/to/M365.test-tenant.local.md go test -tags m365integration -run TestRealTenantProbe -v ./pkg/agent/m365/
//
// The file holds "Tenant ID:", "Client ID:" and "Client Secret:" lines. Nothing
// secret is logged.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	spec "github.com/osshield/fallbck/pkg/m365"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/scan"
	"io"
)

func probeCredentials(t *testing.T) spec.Credentials {
	path := os.Getenv("FALLBCK_M365_CREDENTIALS")
	if path == "" {
		t.Skip("FALLBCK_M365_CREDENTIALS not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c := spec.Credentials{AuthMethod: spec.AuthSecret}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "tenant id":
			c.TenantID = v
		case "client id":
			c.ClientID = v
		case "client secret":
			c.Secret = v
		}
	}
	if c.TenantID == "" || c.ClientID == "" || c.Secret == "" {
		t.Fatal("credentials file lacks Tenant ID, Client ID or Client Secret")
	}
	return c
}

func TestRealTenantProbe(t *testing.T) {
	creds := probeCredentials(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Granted application roles, from the token itself
	src, err := spec.TokenSource(ctx, creds, "")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := src.Token()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if parts := strings.Split(tok.AccessToken, "."); len(parts) == 3 {
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims struct {
			Roles []string `json:"roles"`
		}
		_ = json.Unmarshal(payload, &claims)
		sort.Strings(claims.Roles)
		t.Logf("app roles granted (%d): %s", len(claims.Roles), strings.Join(claims.Roles, " "))
	}

	org, err := spec.TestConnection(ctx, creds, "", "")
	if err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	t.Logf("organization: %s (%s) domains %v", org.DisplayName, org.ID, org.Domains)

	c, err := NewClient(ctx, creds, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Users and selection
	users, warnings, err := SelectUsers(ctx, c, spec.UserSelection{})
	if err != nil {
		t.Fatalf("SelectUsers: %v", err)
	}
	t.Logf("selected users: %d, warnings %v", len(users), warnings)
	for i, u := range users {
		if i < 10 {
			t.Logf("  user %s licensed=%v mail=%q", u.UPN, u.Licensed(), u.Mail)
		}
	}
	if len(users) == 0 {
		t.Fatal("no users selected; nothing more to probe")
	}

	// Mailbox id: field name of /users/{id}/settings/exchange
	var mailboxUser Principal
	var mbx string
	for _, u := range users {
		var raw map[string]any
		err := c.Get(ctx, "users/"+u.ID+"/settings/exchange", &raw, nil)
		if err != nil {
			t.Logf("  %s settings/exchange: %v", u.UPN, err)
			continue
		}
		keys := make([]string, 0, len(raw))
		for k := range raw {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Logf("  %s settings/exchange keys: %v", u.UPN, keys)
		if v, ok := raw["primaryMailboxId"].(string); ok && v != "" {
			mailboxUser, mbx = u, v
			break
		}
		for k, v := range raw {
			if s, ok := v.(string); ok && strings.HasPrefix(s, "MBX:") {
				t.Logf("  !! mailbox id is under key %q, not primaryMailboxId", k)
				mailboxUser, mbx = u, s
			}
		}
		if mbx != "" {
			break
		}
	}
	if mbx == "" {
		t.Fatal("no user with a mailbox id; is MailboxSettings.Read / MailboxItem.Read.All granted?")
	}
	t.Logf("mailbox probe user %s", mailboxUser.UPN)
	base := "admin/exchange/mailboxes/" + mbx

	// Folders: names, parents, root naming
	type folder struct {
		ID, DisplayName, ParentID, Type string
	}
	var folders []folder
	byID := map[string]folder{}
	deltaLink, err := c.Each(ctx, base+"/folders/delta?$select=id,displayName,parentFolderId,type", maxPage, func(raw json.RawMessage) error {
		var f struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			ParentID    string `json:"parentFolderId"`
			Type        string `json:"type"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			return err
		}
		fo := folder{f.ID, f.DisplayName, f.ParentID, f.Type}
		folders = append(folders, fo)
		byID[f.ID] = fo
		return nil
	})
	if err != nil {
		t.Logf("folders/delta: %v  → the folder endpoints need MailboxFolder.Read.All; falling back to the standard mailFolders ids", err)
		var std struct {
			Value []struct {
				ID          string `json:"id"`
				DisplayName string `json:"displayName"`
				ParentID    string `json:"parentFolderId"`
			} `json:"value"`
		}
		if err := c.Get(ctx, "users/"+mailboxUser.ID+"/mailFolders?$select=id,displayName,parentFolderId&$top=100", &std, nil); err != nil {
			t.Fatalf("standard mailFolders: %v", err)
		}
		for _, f := range std.Value {
			fo := folder{f.ID, f.DisplayName, f.ParentID, ""}
			folders = append(folders, fo)
			byID[f.ID] = fo
		}
	}
	t.Logf("folders: %d, deltaLink present=%v", len(folders), deltaLink != "")
	roots := 0
	for _, f := range folders {
		if _, ok := byID[f.ParentID]; !ok {
			roots++
			t.Logf("  ROOT folder %q type=%s parent=%q (not in listing)", f.DisplayName, f.Type, f.ParentID)
		}
	}
	for _, f := range folders {
		if p, ok := byID[f.ParentID]; ok {
			t.Logf("  folder %q type=%s parent=%q", f.DisplayName, f.Type, p.DisplayName)
		}
	}
	t.Logf("root folders: %d (collector assumes the topmost ancestor named like 'Top of Information Store' is dropped)", roots)

	// Items delta of the folder with most items (Inbox preferred)
	var inbox folder
	for _, f := range folders {
		if f.DisplayName == "Inbox" {
			inbox = f
		}
	}
	if inbox.ID == "" && len(folders) > 0 {
		inbox = folders[0]
	}
	type item struct {
		ID, ChangeKey, Type string
		Size                int64
	}
	var items []item
	_, err = c.Each(ctx, base+"/folders/"+inbox.ID+"/items/delta?$select=id,size,changeKey,lastModifiedDateTime,createdDateTime,type", maxPage, func(raw json.RawMessage) error {
		var it mailboxItem
		if err := json.Unmarshal(raw, &it); err != nil {
			return err
		}
		items = append(items, item{it.ID, it.ChangeKey, it.Type, it.Size})
		return nil
	})
	if err != nil {
		t.Fatalf("items/delta of %s (folder id from %s): %v", inbox.DisplayName, map[bool]string{true: "mailboxFolder", false: "standard mailFolders"}[inbox.Type != ""], err)
	}
	t.Logf("folder %q items: %d (folder id usable across both APIs=%v)", inbox.DisplayName, len(items), inbox.Type == "")
	if len(items) == 0 {
		t.Log("no items to export; skipping export and id checks")
		return
	}
	sample := items
	if len(sample) > 3 {
		sample = sample[:3]
	}
	ids := make([]string, 0, len(sample))
	for _, it := range sample {
		ids = append(ids, it.ID)
		t.Logf("  item type=%s size=%d changeKey=%s id=%s…", it.Type, it.Size, it.ChangeKey[:min(12, len(it.ChangeKey))], it.ID[:min(16, len(it.ID))])
	}

	// Export: stream size vs reported size, per-item error field
	var resp struct {
		Value []struct {
			ItemID    string          `json:"itemId"`
			ChangeKey string          `json:"changeKey"`
			Data      string          `json:"data"`
			Error     json.RawMessage `json:"error"`
		} `json:"value"`
	}
	if err := c.Post(ctx, base+"/exportItems", map[string]any{"itemIds": ids}, &resp); err != nil {
		t.Fatalf("exportItems: %v", err)
	}
	for _, v := range resp.Value {
		data, _ := base64.StdEncoding.DecodeString(v.Data)
		var reported int64
		for _, it := range sample {
			if it.ID == v.ItemID {
				reported = it.Size
			}
		}
		t.Logf("  export %s… stream=%d bytes reported size=%d (equal=%v) error=%s", v.ItemID[:min(16, len(v.ItemID))], len(data), reported, int64(len(data)) == reported, string(v.Error))
	}

	// Browsing index: does the standard API know the folder id and the item ids?
	var msgs struct {
		Value []struct {
			ID      string `json:"id"`
			Subject string `json:"subject"`
		} `json:"value"`
	}
	err = c.Get(ctx, "users/"+mailboxUser.ID+"/mailFolders/"+inbox.ID+"/messages?$select=id,subject&$top=50", &msgs, nil)
	if err != nil {
		t.Logf("standard mailFolders/{mailboxFolder id}/messages: %v  → folder ids DIFFER between the APIs", err)
	} else {
		known := map[string]bool{}
		for _, it := range items {
			known[it.ID] = true
		}
		match := 0
		for _, m := range msgs.Value {
			if known[m.ID] {
				match++
			}
		}
		t.Logf("standard messages in that folder: %d, with ids equal to mailboxItem ids: %d (equal ids=%v)", len(msgs.Value), match, match > 0 && match == len(msgs.Value))
	}

	// OneDrive and drive delta
	if ref, err := userDrive(ctx, c, mailboxUser.ID); err != nil {
		t.Logf("userDrive: %v", err)
	} else if ref == nil {
		t.Log("user has no OneDrive")
	} else {
		di := &DriveIndex{ID: ref.ID, Prefix: ref.Prefix}
		entries, dirs, st, err := collectDrive(ctx, c, di, nil, time.Now(), func(w string) { t.Logf("  drive warning: %s", w) })
		if err != nil {
			t.Fatalf("collectDrive: %v", err)
		}
		t.Logf("OneDrive: %d files, %d folders, %d bytes, delta link present=%v", st.Files, st.Folders, st.Bytes, di.Delta != "")
		for i, e := range entries {
			if i < 5 {
				t.Logf("  %s (%d bytes)", e.Path, e.Size)
			}
		}
		_ = dirs
	}

	// Sites and teams
	teams, err := SelectTeams(ctx, c, spec.Selection{})
	if err != nil {
		t.Logf("SelectTeams: %v", err)
	} else {
		t.Logf("teams: %d", len(teams))
		for _, tm := range teams {
			idx := &TeamsIndex{}
			entries, st, err := collectTeam(ctx, c, tm.ID, idx, time.Now(), func(w string) { t.Logf("  team warning: %s", w) })
			if err != nil {
				t.Logf("  team %q: %v", tm.DisplayName, err)
				continue
			}
			t.Logf("  team %q: %d channels, %d messages, %d hosted, %d entries, since=%s", tm.DisplayName, st.Channels, st.Messages, st.Hosted, len(entries), idx.Since)
			break
		}
	}
	teamSites := map[string]bool{}
	sites, err := SelectSites(ctx, c, spec.Selection{}, teamSites)
	if err != nil {
		t.Logf("SelectSites: %v", err)
	} else {
		t.Logf("sites: %d", len(sites))
		for i, s := range sites {
			if i < 5 {
				t.Logf("  site %s", siteKey(s.WebURL))
			}
		}
	}

	// Directory collections: which ones the app may read
	entries, dwarn, err := collectDirectory(ctx, c, time.Now())
	if err != nil {
		t.Fatalf("collectDirectory: %v", err)
	}
	t.Logf("directory entries: %d, warnings: %v", len(entries), dwarn)
	t.Logf("graph requests: %d, retries: %d", c.Stats.Requests.Load(), c.Stats.Retries.Load())
	fmt.Println()
}

// TestRealTenantRun executes the whole Run against the tenant with an upload that reads
// every stream (no PBS): the collectors, the index round trip and the tree are
// exercised on real data. Mailboxes are included only when the app holds
// MailboxFolder.Read.All (set FALLBCK_M365_MAILBOXES=1).
func TestRealTenantRun(t *testing.T) {
	creds := probeCredentials(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	off := false
	s := &spec.Spec{TenantID: [16]byte{1}, Concurrency: 4}
	if os.Getenv("FALLBCK_M365_MAILBOXES") == "" {
		s.Workloads.Mailboxes = &off
	}
	stateDir, spoolDir := t.TempDir(), t.TempDir()
	var total, files int64
	shown := map[string]bool{}
	upload := func(ctx context.Context, u *Unit, tree *scan.Node, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error) {
		if !shown[u.Kind] {
			shown[u.Kind] = true
			var paths []string
			var list func(n *scan.Node, prefix string)
			list = func(n *scan.Node, prefix string) {
				for _, c := range n.Children {
					p := prefix + "/" + c.Name
					if c.Kind == scan.KindDirectory {
						list(c, p)
					} else {
						paths = append(paths, p)
					}
				}
			}
			list(tree, "")
			sort.Strings(paths)
			if len(paths) > 12 {
				paths = append(paths[:6], append([]string{"…"}, paths[len(paths)-6:]...)...)
			}
			t.Logf("  %s %s tree (%s.pxar): %s", u.Kind, u.Name, u.Archive, strings.Join(paths, " | "))
		}
		var walk func(n *scan.Node, prefix string) error
		walk = func(n *scan.Node, prefix string) error {
			for _, c := range n.Children {
				p := prefix + "/" + c.Name
				switch c.Kind {
				case scan.KindDirectory:
					if err := walk(c, p); err != nil {
						return err
					}
				case scan.KindStream:
					data, err := io.ReadAll(c.Stream)
					if err != nil {
						return fmt.Errorf("%s: %w", p, err)
					}
					if int64(len(data)) != c.Stat.Size {
						t.Errorf("%s %s: stream yields %d bytes, declared %d", u.Group, p, len(data), c.Stat.Size)
					}
					total += int64(len(data))
					files++
				}
			}
			return nil
		}
		if err := walk(tree, ""); err != nil {
			return nil, err
		}
		return &temporal.BackupExecutionResult{Status: "completed", SnapshotID: "host/" + u.Group + "/" + time.Now().UTC().Format("2006-01-02T15:04:05Z")}, nil
	}
	for run := 1; run <= 2; run++ {
		before := total
		session := &temporal.BackupSessionInfo{JobID: [16]byte{2}, BackupRunID: [16]byte{byte(run)}, BackupType: "host", BackupID: "m365-probe", JobName: "probe"}
		res, err := Run(ctx, RunOptions{Session: session, Spec: s, Credentials: creds, StateDir: stateDir, SpoolDir: spoolDir, Upload: upload, Hostname: "probe", Version: "test"})
		if err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		var m spec.Manifest
		_ = json.Unmarshal(res.Details, &struct {
			Manifest *spec.Manifest `json:"manifest"`
		}{&m})
		t.Logf("run %d: status=%s error=%q units=%d files read=%d bytes read=%d warnings=%d", run, res.Status, res.ErrorMessage, len(m.Units), files, total-before, len(m.Warnings))
		for _, u := range m.Units {
			var arch []string
			for _, a := range u.Archives {
				arch = append(arch, fmt.Sprintf("%s=%d items/%d B fetched", a.Name, a.Items, a.Downloaded))
			}
			t.Logf("  %s %s → %s %s %v %s", u.Kind, u.Name, u.Status, u.Error, u.Warnings, strings.Join(arch, ", "))
		}
		for _, w := range m.Warnings {
			t.Logf("  warning: %s", w)
		}
	}
}
