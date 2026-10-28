package m365

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	spec "github.com/osshield/fallbck/pkg/m365"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/scan"
)

const (
	tenantGUID = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	clientGUID = "11111111-2222-3333-4444-555555555555"
)

// fakeItem is one mailbox item or drive item of the fake tenant
type fakeItem struct {
	id, changeKey, class string
	size                 int
	ver                  int
	removed              bool
	// drives
	path    string
	dir     bool
	content string
}

// fakeGraph is a small tenant: two users, one site, one team; every delta collection
// carries a version counter so a saved delta token only returns later changes
type fakeGraph struct {
	mu       sync.Mutex
	cmu      sync.Mutex // guards calls (handlers hold mu while counting)
	ver      int
	folders  map[string]*fakeItem            // mailbox folders by id (class = type, path = displayName)
	items    map[string]map[string]*fakeItem // folder id → items
	drives   map[string]map[string]*fakeItem // drive id → items
	messages []json.RawMessage
	calls    map[string]int
	exports  [][]string
	failUser string // user id whose export answers 500
	expired  map[string]bool
}

func newFakeGraph() *fakeGraph {
	g := &fakeGraph{folders: map[string]*fakeItem{}, items: map[string]map[string]*fakeItem{}, drives: map[string]map[string]*fakeItem{}, calls: map[string]int{}, expired: map[string]bool{}}
	g.folders["root"] = &fakeItem{id: "root", path: "Top of Information Store", class: "IPF.Note"}
	g.folders["inbox"] = &fakeItem{id: "inbox", path: "Inbox", class: "IPF.Note"}
	g.folders["junk"] = &fakeItem{id: "junk", path: "Junk Email", class: "IPF.Note"}
	g.items["inbox"] = map[string]*fakeItem{}
	g.items["junk"] = map[string]*fakeItem{"j1": {id: "j1", changeKey: "ck", class: "IPM.Note", size: 10}}
	for i := 0; i < 21; i++ {
		id := fmt.Sprintf("m%02d", i)
		g.items["inbox"][id] = &fakeItem{id: id, changeKey: "ck1", class: "IPM.Note", size: 1000}
	}
	g.items["inbox"]["appt"] = &fakeItem{id: "appt", changeKey: "ck1", class: "IPM.Appointment", size: 500}
	g.drives["d-alice"] = map[string]*fakeItem{
		"f1": {id: "f1", path: "/drive/root:", dir: true, content: "Documents"},
		"a":  {id: "a", path: "/drive/root:/Documents", content: "hello world", changeKey: "c1"},
		"n":  {id: "n", path: "/drive/root:/Documents", content: "notes", changeKey: "c1"},
	}
	g.drives["d-site"] = map[string]*fakeItem{"s1": {id: "s1", path: "/drives/d-site/root:", content: "plan.txt", changeKey: "c1"}}
	g.drives["d-team"] = map[string]*fakeItem{"t1": {id: "t1", path: "/drives/d-team/root:", content: "agenda", changeKey: "c1"}}
	g.messages = []json.RawMessage{json.RawMessage(`{"id":"1700000000001","createdDateTime":"2026-10-01T10:00:00Z","lastModifiedDateTime":"2026-10-01T10:00:00Z","channelIdentity":{"channelId":"ch1"},"body":{"contentType":"html","content":"<img src=\"https://graph.microsoft.com/v1.0/teams/team1/channels/ch1/messages/1700000000001/hostedContents/h1/$value\">"}}`)}
	return g
}

func (g *fakeGraph) bump() int { g.ver++; return g.ver }

// delta answers a delta query over the given items with the token protocol
func (g *fakeGraph) delta(w http.ResponseWriter, r *http.Request, items map[string]*fakeItem, render func(it *fakeItem) map[string]any) {
	tok := r.URL.Query().Get("$deltatoken")
	if g.expired[r.URL.Path+"|"+tok] {
		http.Error(w, `{"error":{"code":"syncStateNotFound","message":"resync"}}`, http.StatusGone)
		return
	}
	since, _ := strconv.Atoi(tok)
	var value []map[string]any
	ids := make([]string, 0, len(items))
	for id := range items {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		it := items[id]
		if it.ver <= since && tok != "" {
			continue
		}
		if it.removed {
			if tok != "" {
				value = append(value, map[string]any{"id": it.id, "@removed": map[string]string{"reason": "deleted"}})
			}
			continue
		}
		value = append(value, render(it))
	}
	base := r.URL.Path
	writeJSON(w, map[string]any{"value": value, "@odata.deltaLink": "http://" + r.Host + base + "?$deltatoken=" + strconv.Itoa(g.ver)})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (g *fakeGraph) handler(_ *testing.T) http.Handler {
	mux := http.NewServeMux()
	count := func(key string) {
		g.cmu.Lock()
		g.calls[key]++
		g.cmu.Unlock()
	}
	mux.HandleFunc("/"+tenantGUID+"/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		count("token")
		writeJSON(w, map[string]any{"token_type": "Bearer", "expires_in": 3599, "access_token": "tok"})
	})
	mux.HandleFunc("/v1.0/organization", func(w http.ResponseWriter, r *http.Request) {
		count("organization")
		writeJSON(w, map[string]any{"value": []map[string]any{{"id": tenantGUID, "displayName": "Contoso", "verifiedDomains": []map[string]string{{"name": "contoso.com"}}}}})
	})
	mux.HandleFunc("/v1.0/users", func(w http.ResponseWriter, r *http.Request) {
		count("users")
		if r.URL.Query().Get("$skiptoken") == "" {
			writeJSON(w, map[string]any{"value": []map[string]any{
				{"id": "u-alice", "userPrincipalName": "alice@contoso.com", "displayName": "Alice", "mail": "alice@contoso.com", "userType": "Member", "accountEnabled": true, "assignedLicenses": []map[string]string{{"skuId": "x"}}},
				{"id": "u-guest", "userPrincipalName": "guest_ext#EXT#@contoso.com", "userType": "Guest", "assignedLicenses": []map[string]string{{"skuId": "x"}}},
			}, "@odata.nextLink": "http://" + r.Host + "/v1.0/users?$skiptoken=2"})
			return
		}
		writeJSON(w, map[string]any{"value": []map[string]any{
			{"id": "u-bob", "userPrincipalName": "bob@contoso.com", "displayName": "Bob", "mail": "bob@contoso.com", "userType": "Member", "accountEnabled": true, "assignedLicenses": []map[string]string{{"skuId": "x"}}},
			{"id": "u-shared", "userPrincipalName": "info@contoso.com", "displayName": "Info", "mail": "info@contoso.com", "userType": "Member", "accountEnabled": true, "assignedLicenses": []map[string]string{}},
			{"id": "u-nolic", "userPrincipalName": "svc@contoso.com", "displayName": "Svc", "userType": "Member", "accountEnabled": true, "assignedLicenses": []map[string]string{}},
		}})
	})
	mux.HandleFunc("/v1.0/users/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/v1.0/users/")
		user, _, _ := strings.Cut(rest, "/")
		switch {
		case strings.HasSuffix(rest, "/settings/exchange"):
			count("exchange-settings")
			if user == "u-shared" {
				http.Error(w, `{"error":{"code":"ResourceNotFound","message":"no mailbox"}}`, http.StatusNotFound)
				return
			}
			writeJSON(w, map[string]any{"primaryMailboxId": "MBX:" + user})
		case strings.HasSuffix(rest, "/drive"):
			count("drive")
			if user != "u-alice" {
				http.Error(w, `{"error":{"code":"ResourceNotFound","message":"no drive"}}`, http.StatusNotFound)
				return
			}
			writeJSON(w, map[string]any{"id": "d-alice", "name": "OneDrive", "webUrl": "https://contoso-my.sharepoint.com/personal/alice"})
		case strings.Contains(rest, "/mailFolders/") && strings.HasSuffix(rest, "/messages/delta"):
			count("browse")
			fid := strings.Split(rest, "/")[2]
			g.mu.Lock()
			defer g.mu.Unlock()
			g.delta(w, r, g.items[fid], func(it *fakeItem) map[string]any {
				return map[string]any{"id": it.id, "subject": "Subject " + it.id, "receivedDateTime": "2026-10-01T00:00:00Z", "from": map[string]any{"emailAddress": map[string]string{"name": "Bob", "address": "bob@contoso.com"}}}
			})
		default:
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc("/v1.0/admin/exchange/mailboxes/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/v1.0/admin/exchange/mailboxes/")
		mbx, op, _ := strings.Cut(rest, "/")
		user := strings.TrimPrefix(mbx, "MBX:")
		g.mu.Lock()
		defer g.mu.Unlock()
		switch {
		case op == "folders/delta":
			count("folders-delta")
			g.delta(w, r, g.folders, func(it *fakeItem) map[string]any {
				parent := "root"
				if it.id == "root" {
					parent = ""
				}
				return map[string]any{"id": it.id, "displayName": it.path, "parentFolderId": parent, "type": it.class}
			})
		case strings.HasPrefix(op, "folders/") && strings.HasSuffix(op, "/items/delta"):
			count("items-delta")
			fid := strings.Split(op, "/")[1]
			g.delta(w, r, g.items[fid], func(it *fakeItem) map[string]any {
				return map[string]any{"id": it.id, "changeKey": it.changeKey, "size": it.size, "type": it.class, "createdDateTime": "2026-10-01T09:00:00Z", "lastModifiedDateTime": "2026-10-01T10:00:00Z"}
			})
		case op == "exportItems":
			count("export")
			if user == g.failUser {
				http.Error(w, `{"error":{"code":"ErrorInternalServerError","message":"boom"}}`, http.StatusInternalServerError)
				return
			}
			var req struct {
				ItemIDs []string `json:"itemIds"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			g.exports = append(g.exports, req.ItemIDs)
			var value []map[string]any
			for _, id := range req.ItemIDs {
				// The export stream is deliberately larger than the reported size
				data := strings.Repeat(id+":", 300)
				value = append(value, map[string]any{"itemId": id, "changeKey": "ck", "data": base64.StdEncoding.EncodeToString([]byte(data))})
			}
			writeJSON(w, map[string]any{"value": value})
		default:
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc("/v1.0/drives/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/v1.0/drives/")
		drive, op, _ := strings.Cut(rest, "/")
		g.mu.Lock()
		defer g.mu.Unlock()
		switch {
		case op == "root/delta":
			count("drive-delta")
			g.delta(w, r, g.drives[drive], func(it *fakeItem) map[string]any {
				m := map[string]any{"id": it.id, "name": it.content, "size": len(it.content), "cTag": it.changeKey, "lastModifiedDateTime": "2026-10-01T10:00:00Z",
					"parentReference": map[string]string{"path": it.path}, "webUrl": "https://x/" + it.id, "lastModifiedBy": map[string]any{"user": map[string]string{"displayName": "Alice"}}}
				if it.dir {
					m["folder"] = map[string]any{}
				} else {
					m["file"] = map[string]any{}
				}
				return m
			})
		case strings.HasPrefix(op, "items/") && strings.HasSuffix(op, "/content"):
			count("download")
			id := strings.Split(op, "/")[1]
			it := g.drives[drive][id]
			if it == nil {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, it.content)
		default:
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc("/v1.0/sites", func(w http.ResponseWriter, r *http.Request) {
		count("sites")
		writeJSON(w, map[string]any{"value": []map[string]any{
			{"id": "site-hr", "name": "HR", "displayName": "HR", "webUrl": "https://contoso.sharepoint.com/sites/HR"},
			{"id": "site-team", "name": "Team", "displayName": "Team One", "webUrl": "https://contoso.sharepoint.com/sites/TeamOne"},
		}})
	})
	mux.HandleFunc("/v1.0/sites/", func(w http.ResponseWriter, r *http.Request) {
		count("site-drives")
		site := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1.0/sites/"), "/")[0]
		drive := "d-site"
		if site == "site-team" {
			drive = "d-team"
		}
		writeJSON(w, map[string]any{"value": []map[string]any{{"id": drive, "name": "Documents", "webUrl": "https://x/" + drive}}})
	})
	mux.HandleFunc("/v1.0/groups", func(w http.ResponseWriter, r *http.Request) {
		count("groups")
		if strings.Contains(r.URL.RawQuery, "Team") {
			writeJSON(w, map[string]any{"value": []map[string]any{{"id": "team1", "displayName": "Team One"}}})
			return
		}
		writeJSON(w, map[string]any{"value": []map[string]any{}})
	})
	mux.HandleFunc("/v1.0/groups/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/sites/root") {
			count("team-site")
			writeJSON(w, map[string]any{"id": "site-team", "webUrl": "https://contoso.sharepoint.com/sites/TeamOne"})
			return
		}
		writeJSON(w, map[string]any{"value": []map[string]any{}})
	})
	mux.HandleFunc("/v1.0/teams/team1/channels", func(w http.ResponseWriter, r *http.Request) {
		count("channels")
		writeJSON(w, map[string]any{"value": []map[string]any{{"id": "ch1", "displayName": "General", "membershipType": "standard"}}})
	})
	mux.HandleFunc("/v1.0/teams/team1/channels/getAllMessages", func(w http.ResponseWriter, r *http.Request) {
		count("messages")
		g.mu.Lock()
		defer g.mu.Unlock()
		filter := r.URL.Query().Get("$filter")
		var out []json.RawMessage
		for _, m := range g.messages {
			var mm struct {
				Modified string `json:"lastModifiedDateTime"`
			}
			_ = json.Unmarshal(m, &mm)
			since := ""
			if f := strings.Fields(filter); len(f) >= 3 {
				since = f[2]
			}
			if filter == "" || mm.Modified > since {
				out = append(out, m)
			}
		}
		if out == nil {
			out = []json.RawMessage{}
		}
		writeJSON(w, map[string]any{"value": out})
	})
	mux.HandleFunc("/v1.0/teams/team1/channels/ch1/messages/", func(w http.ResponseWriter, r *http.Request) {
		count("hosted")
		_, _ = io.WriteString(w, "PNGDATA")
	})
	mux.HandleFunc("/v1.0/teams/team1", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"id": "team1", "displayName": "Team One"})
	})
	// Directory collections: empty lists, conditional access forbidden
	mux.HandleFunc("/v1.0/", func(w http.ResponseWriter, r *http.Request) {
		count("directory")
		if strings.Contains(r.URL.Path, "conditionalAccess") {
			http.Error(w, `{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}`, http.StatusForbidden)
			return
		}
		writeJSON(w, map[string]any{"value": []map[string]any{}})
	})
	return mux
}

// treePaths lists the file paths of a tree and reads every stream when read is set
func treePaths(t *testing.T, n *scan.Node, prefix string, read bool) []string {
	t.Helper()
	var out []string
	for _, c := range n.Children {
		p := c.Name
		if prefix != "" {
			p = prefix + "/" + c.Name
		}
		switch c.Kind {
		case scan.KindDirectory:
			out = append(out, treePaths(t, c, p, read)...)
		case scan.KindStream:
			out = append(out, p)
			if read {
				data, err := io.ReadAll(c.Stream)
				if err != nil {
					t.Fatalf("%s: %v", p, err)
				}
				if int64(len(data)) != c.Stat.Size {
					t.Errorf("%s: stream yields %d bytes, declared %d", p, len(data), c.Stat.Size)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

type uploaded struct {
	unit  *Unit
	paths []string
	blobs []string
}

// runOnce executes Run against the fake; the upload reads every stream when read is set
func runOnce(t *testing.T, _ *fakeGraph, srv *httptest.Server, stateDir, spoolDir string, runID uuid.UUID, read bool, s *spec.Spec) (*temporal.BackupExecutionResult, map[string]uploaded, error) {
	t.Helper()
	var mu sync.Mutex
	ups := map[string]uploaded{}
	upload := func(ctx context.Context, u *Unit, tree *scan.Node, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error) {
		paths := treePaths(t, tree, "", read)
		var names []string
		for _, b := range blobs {
			names = append(names, b.Name)
		}
		mu.Lock()
		ups[u.Group] = uploaded{unit: u, paths: paths, blobs: names}
		mu.Unlock()
		return &temporal.BackupExecutionResult{Status: "completed", SnapshotID: "host/" + u.Group + "/2026-10-10T01:00:00Z", BytesScanned: 100}, nil
	}
	session := &temporal.BackupSessionInfo{JobID: uuid.New(), BackupRunID: runID, BackupType: "host", BackupID: "m365-contoso", JobName: "Contoso"}
	res, err := Run(context.Background(), RunOptions{
		Session: session, Spec: s,
		Credentials: spec.Credentials{TenantID: tenantGUID, ClientID: clientGUID, AuthMethod: spec.AuthSecret, Secret: "s"},
		StateDir:    stateDir, SpoolDir: spoolDir, Upload: upload,
		Authority: srv.URL, GraphURL: srv.URL, Hostname: "agent1", Version: "test",
	})
	return res, ups, err
}

func TestRunTwice(t *testing.T) {
	g := newFakeGraph()
	srv := httptest.NewServer(g.handler(t))
	defer srv.Close()
	stateDir, spoolDir := t.TempDir(), t.TempDir()
	s := &spec.Spec{TenantID: uuid.New(), ExcludeTypes: []string{"IPM.Appointment"}, Concurrency: 2}

	// Run 1: everything is new; every stream is read
	res, ups, err := runOnce(t, g, srv, stateDir, spoolDir, uuid.New(), true, s)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "completed" || res.ErrorMessage != "" {
		t.Fatalf("run 1: %+v", res)
	}
	// info@ (shared mailbox without mailbox or OneDrive in the fake) is skipped: no snapshot
	want := []string{"m365-contoso", "m365-contoso-site-contoso.sharepoint.com-sites-hr", "m365-contoso-team-team-one",
		"m365-contoso-user-alice_contoso.com", "m365-contoso-user-bob_contoso.com"}
	var groups []string
	for g := range ups {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	if strings.Join(groups, " ") != strings.Join(want, " ") {
		t.Fatalf("groups %v, want %v", groups, want)
	}
	alice := ups["m365-contoso-user-alice_contoso.com"]
	if alice.unit.Archive != ArchiveUser || len(alice.blobs) != 1 || alice.blobs[0] != spec.UnitManifestName {
		t.Errorf("alice unit: %+v", alice)
	}
	has := func(paths []string, want ...string) {
		t.Helper()
		for _, w := range want {
			found := false
			for _, p := range paths {
				if p == w || strings.HasPrefix(p, w) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("missing %s in %v", w, paths)
			}
		}
	}
	has(alice.paths, "mailbox/Inbox/20261001T090000Z-", "mailbox/Inbox/index.json", "mailbox/folders.json", "onedrive/Documents/hello world", "onedrive/.fallbck/items.json", spec.UnitManifestName)
	for _, p := range alice.paths {
		if strings.Contains(p, "Junk") || strings.Contains(p, "Top of Information Store") || strings.Contains(p, shortID("appt")) {
			t.Errorf("excluded content archived: %s", p)
		}
	}
	// 21 mail items + the browse index; the appointment is excluded by class
	n := 0
	for _, p := range alice.paths {
		if strings.HasSuffix(p, ".exoitem") {
			n++
		}
	}
	if n != 21 {
		t.Errorf("alice has %d items, want 21", n)
	}
	has(ups["m365-contoso-team-team-one"].paths, "messages/General/2026-10.json", "hosted/", "files/Documents/agenda", "team.json", "channels.json")
	has(ups["m365-contoso-site-contoso.sharepoint.com-sites-hr"].paths, "files/Documents/plan.txt")
	has(ups["m365-contoso"].paths, spec.ManifestBlobName, "RESTORE.md", "users.json", "organization.json")
	if ups["m365-contoso"].blobs[0] != spec.ManifestBlobName {
		t.Errorf("directory blobs %v", ups["m365-contoso"].blobs)
	}
	// Export batching: 21 items for alice → 2 calls, same for bob
	if g.calls["export"] != 4 {
		t.Errorf("export calls %d, want 4 (2 per mailbox)", g.calls["export"])
	}
	for _, ids := range g.exports {
		if len(ids) > exportBatchItems {
			t.Errorf("batch of %d ids", len(ids))
		}
	}
	// The shared mailbox has no Exchange mailbox and no OneDrive: skipped, not failed
	var m spec.Manifest
	if err := json.Unmarshal(res.Details, &struct {
		Manifest *spec.Manifest `json:"manifest"`
	}{&m}); err != nil {
		t.Fatal(err)
	}
	for _, u := range m.Units {
		if u.Name == "info@contoso.com" && u.Status != "skipped" {
			t.Errorf("shared mailbox unit: %+v", u)
		}
	}
	if len(m.Warnings) == 0 || !strings.Contains(strings.Join(m.Warnings, " "), "conditional-access") {
		t.Errorf("forbidden directory collection must be a warning: %v", m.Warnings)
	}

	// Run 2: one changed mail item, one deleted file, one new file, one new message;
	// nothing is read by the upload (gopbs reuses everything unchanged)
	g.mu.Lock()
	g.items["inbox"]["m05"].changeKey, g.items["inbox"]["m05"].ver = "ck2", g.bump()
	g.drives["d-alice"]["n"].removed, g.drives["d-alice"]["n"].ver = true, g.bump()
	g.drives["d-alice"]["new"] = &fakeItem{id: "new", path: "/drive/root:/Documents", content: "fresh", changeKey: "c1", ver: g.bump()}
	g.messages = append(g.messages, json.RawMessage(`{"id":"1700000000002","createdDateTime":"2026-11-02T10:00:00Z","lastModifiedDateTime":"2026-11-02T10:00:00Z","channelIdentity":{"channelId":"ch1"},"body":{"contentType":"text","content":"hi"}}`))
	calls1 := map[string]int{}
	for k, v := range g.calls {
		calls1[k] = v
	}
	g.exports = nil
	g.mu.Unlock()

	res, ups, err = runOnce(t, g, srv, stateDir, spoolDir, uuid.New(), false, s)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "completed" {
		t.Fatalf("run 2: %+v", res)
	}
	// Both mailboxes share the fake's folders: one export of m05 per mailbox
	if len(g.exports) != 2 || len(g.exports[0]) != 1 || g.exports[0][0] != "m05" || len(g.exports[1]) != 1 || g.exports[1][0] != "m05" {
		t.Errorf("run 2 exports %v, want only m05 per mailbox", g.exports)
	}
	if g.calls["download"] != calls1["download"] {
		t.Errorf("run 2 downloaded drive content: %d → %d", calls1["download"], g.calls["download"])
	}
	alice = ups["m365-contoso-user-alice_contoso.com"]
	has(alice.paths, "onedrive/Documents/fresh")
	for _, p := range alice.paths {
		if p == "onedrive/Documents/notes" {
			t.Error("deleted file still archived")
		}
	}
	has(ups["m365-contoso-team-team-one"].paths, "messages/General/2026-10.json", "messages/General/2026-11.json")
	if g.calls["hosted"] != calls1["hosted"] {
		t.Error("hosted content fetched again")
	}

	// Run 3: the saved items delta of the inbox is expired → full re-enumeration,
	// but unchanged change keys are not exported again
	idx, err := State{Dir: stateDir}.Load("m365-contoso-user-alice_contoso.com")
	if err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	for _, f := range idx.Mailbox.Folders {
		if f.Name == "Inbox" {
			u, err := url.Parse(f.ItemsDelta)
			if err != nil {
				t.Fatal(err)
			}
			g.expired[u.Path+"|"+u.Query().Get("$deltatoken")] = true
		}
	}
	g.exports = nil
	g.mu.Unlock()
	res, _, err = runOnce(t, g, srv, stateDir, spoolDir, uuid.New(), false, s)
	if err != nil || res.Status != "completed" {
		t.Fatalf("run 3: %v %+v", err, res)
	}
	if len(g.exports) != 0 {
		t.Errorf("run 3 exported %v after a resync", g.exports)
	}
	if err := json.Unmarshal(res.Details, &struct {
		Manifest *spec.Manifest `json:"manifest"`
	}{&m}); err != nil {
		t.Fatal(err)
	}
	for _, u := range m.Units {
		if u.Name == "alice@contoso.com" && u.Resyncs != 1 {
			t.Errorf("alice resyncs %d, want 1", u.Resyncs)
		}
	}
}

func TestRunFailedUnitAndRetrySkip(t *testing.T) {
	g := newFakeGraph()
	g.failUser = "u-bob"
	srv := httptest.NewServer(g.handler(t))
	defer srv.Close()
	stateDir := t.TempDir()
	off := false
	s := &spec.Spec{TenantID: uuid.New(), Workloads: spec.Workloads{Sites: &off, Teams: &off, Entra: &off}}
	runID := uuid.New()
	res, ups, err := runOnce(t, g, srv, stateDir, t.TempDir(), runID, true, s)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "partial" || !strings.HasPrefix(res.ErrorMessage, "1 of 3 units failed") || !strings.Contains(res.ErrorMessage, "bob@contoso.com") {
		t.Fatalf("result %+v", res)
	}
	if _, ok := ups["m365-contoso-user-bob_contoso.com"]; ok {
		t.Error("failed unit must not upload")
	}
	// Bob's index must not have been saved; Alice's was
	if _, err := filepath.Glob(stateDir + "/*bob*"); err == nil {
		matches, _ := filepath.Glob(stateDir + "/*bob*")
		if len(matches) != 0 {
			t.Error("index of the failed unit was saved")
		}
	}
	// The same run again (an activity retry): alice is skipped, bob retried and fails again
	g.mu.Lock()
	g.exports = nil
	g.mu.Unlock()
	res, ups, err = runOnce(t, g, srv, stateDir, t.TempDir(), runID, true, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ups["m365-contoso-user-alice_contoso.com"]; ok {
		t.Error("finished unit uploaded again on retry")
	}
	var m spec.Manifest
	_ = json.Unmarshal(res.Details, &struct {
		Manifest *spec.Manifest `json:"manifest"`
	}{&m})
	for _, u := range m.Units {
		if u.Name == "alice@contoso.com" && (u.Status != "completed" || len(u.Warnings) == 0) {
			t.Errorf("alice on retry: %+v", u)
		}
	}
	// Every unit failing fails the run
	g.mu.Lock()
	g.failUser = "u-alice"
	g.mu.Unlock()
	only := &spec.Spec{TenantID: uuid.New(), Workloads: spec.Workloads{Sites: &off, Teams: &off, Entra: &off, OneDrive: &off}, Users: spec.UserSelection{Include: []string{"alice@*"}}}
	res, _, err = runOnce(t, g, srv, t.TempDir(), t.TempDir(), uuid.New(), true, only)
	if err == nil || res == nil || res.Status != "failed" {
		t.Fatalf("all units failing: err=%v res=%+v", err, res)
	}
}

func TestBuildTree(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	entries := []Entry{
		memEntry("b/c/file.txt", []byte("x"), now),
		memEntry("a.txt", []byte("yy"), now),
		{Path: "b/d/name/with/slash", Size: 0},
	}
	root, err := BuildTree("user", entries, []Dir{{Path: "empty/dir", Mtime: now}}, now)
	if err != nil {
		t.Fatal(err)
	}
	paths := treePaths(t, root, "", true)
	if strings.Join(paths, " ") != "a.txt b/c/file.txt b/d/name/with/slash" {
		t.Errorf("paths %v", paths)
	}
	var names []string
	for _, c := range root.Children {
		names = append(names, c.Name)
	}
	if strings.Join(names, " ") != "a.txt b empty" {
		t.Errorf("root children %v", names)
	}
	if _, err := BuildTree("u", []Entry{memEntry("x", nil, now), memEntry("x", nil, now)}, nil, now); err == nil {
		t.Error("duplicate path accepted")
	}
	if safeComponent("a/b") != "a_b" || safeComponent("..") != "_.." || safeComponent("  ") != "_" {
		t.Error("safeComponent")
	}
}
