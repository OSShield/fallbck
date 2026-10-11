package m365

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	spec "github.com/osshield/fallbck/pkg/m365"
	"github.com/osshield/fallbck/pkg/rundetail"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/scan"
)

// Archive names: one archive per unit snapshot
const (
	ArchiveUser  = "user" // mailbox/ + onedrive/
	ArchiveSite  = "site" // files/<library>/
	ArchiveTeam  = "team" // messages/, hosted/, files/<library>/
	ArchiveEntra = spec.ArchiveEntra
)

// Unit is one snapshot of the run: a user, a site, a team or the directory
type Unit struct {
	Kind     string
	Name     string
	ObjectID string
	Group    string
	// Archive is the pxar name of the unit
	Archive string
	// Principal / Site / Team carry the Graph object
	Principal *Principal
	Site      *Site
	Team      *Team
}

// UploadFunc writes one unit snapshot: the caller mints the unit's ticket, opens the
// transport and runs the backup engine with the tree and the blobs
type UploadFunc func(ctx context.Context, unit *Unit, tree *scan.Node, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error)

// RunOptions parameterise Run
type RunOptions struct {
	Session     *temporal.BackupSessionInfo
	Spec        *spec.Spec
	Credentials spec.Credentials
	// StateDir holds the job's unit indexes (<data>/m365-state/<job id>)
	StateDir string
	// SpoolDir receives exported mailbox items while a unit uploads (<spool>/<run id>)
	SpoolDir string
	Upload   UploadFunc
	Progress func(phase string)
	Items    func(items map[string]rundetail.ProgressItem)
	Hostname string
	Version  string
	// Client overrides the Graph client (tests); Authority / GraphURL point at a fake
	Client    *Client
	Authority string
	GraphURL  string
	Now       func() time.Time
}

// Run executes one Microsoft 365 backup: precheck → select units → one snapshot per
// unit (Concurrency in flight) → the directory snapshot with the run manifest
func Run(ctx context.Context, o RunOptions) (*temporal.BackupExecutionResult, error) {
	if o.Session == nil || o.Upload == nil {
		return nil, errors.New("m365: session and upload are required")
	}
	s := o.Spec.Clone()
	if s == nil {
		return nil, &dbrun.PrecheckError{Msg: "the job has no Microsoft 365 configuration"}
	}
	if err := s.Validate(); err != nil {
		return nil, &dbrun.PrecheckError{Msg: "invalid job configuration", Err: err}
	}
	now := o.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	progress := o.Progress
	if progress == nil {
		progress = func(string) {}
	}
	items := o.Items
	if items == nil {
		items = func(map[string]rundetail.ProgressItem) {}
	}
	started := now()

	c := o.Client
	if c == nil {
		var err error
		if c, err = NewClient(ctx, o.Credentials, o.Authority, o.GraphURL); err != nil {
			return nil, &dbrun.PrecheckError{Msg: "tenant credentials", Err: err}
		}
	}
	progress("connecting to Microsoft Graph")
	org, err := spec.TestConnection(ctx, o.Credentials, o.Authority, o.GraphURL)
	if err != nil && o.Client == nil {
		return nil, &dbrun.PrecheckError{Msg: "Microsoft Graph", Err: err,
			Hint: "check the tenant's credentials and that the agent host reaches login.microsoftonline.com and graph.microsoft.com"}
	}
	if org == nil {
		org = &spec.Organization{}
	}

	manifest := &spec.Manifest{
		SchemaVersion: spec.ManifestSchemaVersion,
		Generator:     spec.Generator{Agent: "fallbck-agent", Version: o.Version, Hostname: o.Hostname},
		Job:           spec.JobInfo{ID: o.Session.JobID.String(), Name: o.Session.JobName, RunID: o.Session.RunID, BackupRunID: o.Session.BackupRunID.String(), Group: o.Session.BackupID},
		Tenant:        spec.TenantInfo{ID: org.ID, DisplayName: org.DisplayName},
		StartedAt:     started,
		Spec:          s,
		Restore:       restoreNotes(o.Session.BackupType, o.Session.BackupID),
	}
	var mu sync.Mutex
	warn := func(format string, args ...any) {
		mu.Lock()
		manifest.Warnings = append(manifest.Warnings, fmt.Sprintf(format, args...))
		mu.Unlock()
	}

	progress("selecting users, sites and teams")
	units, err := selectUnits(ctx, c, s, o.Session.BackupID, warn)
	if err != nil {
		return nil, &dbrun.PrecheckError{Msg: "selecting what to back up", Err: err}
	}
	state := State{Dir: o.StateDir}
	live := map[string]rundetail.ProgressItem{}
	for _, u := range units {
		live[u.Group] = rundetail.ProgressItem{Name: u.Name, Kind: u.Kind, Status: "pending"}
	}
	items(live)

	// Units in parallel, bounded by Concurrency
	results := make([]spec.UnitResult, len(units))
	sem := make(chan struct{}, s.EffConcurrency())
	var wg sync.WaitGroup
	var done, failed int
	for i := range units {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			u := &units[i]
			item := live[u.Group]
			item.Status = "running"
			items(map[string]rundetail.ProgressItem{u.Group: item})
			res := backupUnit(ctx, c, s, state, o, u, now, warn)
			mu.Lock()
			results[i] = res
			done++
			if res.Status == "failed" {
				failed++
			}
			n, f := done, failed
			mu.Unlock()
			item.Status, item.Error = res.Status, res.Error
			if res.SnapshotTime > 0 {
				item.SnapshotID = fmt.Sprintf("%s/%s/%s", o.Session.BackupType, u.Group, time.Unix(res.SnapshotTime, 0).UTC().Format("2006-01-02T15:04:05Z"))
			}
			for _, a := range res.Archives {
				item.BytesUploaded += int64(a.Downloaded)
			}
			items(map[string]rundetail.ProgressItem{u.Group: item})
			progress(fmt.Sprintf("%d of %d units done (%d failed)", n, len(units), f))
		}(i)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	manifest.Units = results

	// The directory snapshot (the job's own group) carries the run manifest
	total := &temporal.BackupExecutionResult{Status: "completed"}
	for _, r := range results {
		for _, a := range r.Archives {
			total.BytesScanned += int64(a.Bytes)
			total.BytesUploaded += int64(a.Downloaded)
		}
	}
	dirUnit := &Unit{Kind: "directory", Name: "directory", Group: o.Session.BackupID, Archive: ArchiveEntra}
	progress("archiving the directory")
	var entries []Entry
	if s.Workloads.EffEntra() {
		var warnings []string
		entries, warnings, err = collectDirectory(ctx, c, now())
		if err != nil {
			return nil, fmt.Errorf("directory: %w", err)
		}
		for _, w := range warnings {
			warn("%s", w)
		}
	}
	manifest.FinishedAt = now()
	data, _ := json.MarshalIndent(manifest, "", "  ")
	entries = append(entries, memEntry(spec.ManifestBlobName, data, now()), memEntry("RESTORE.md", []byte(restoreReadme(manifest)), now()))
	tree, err := BuildTree(ArchiveEntra, entries, nil, now())
	if err != nil {
		return nil, err
	}
	dirResult, err := o.Upload(ctx, dirUnit, tree, []gopbs.Blob{{Name: spec.ManifestBlobName, Data: data}})
	if err != nil {
		return nil, fmt.Errorf("directory snapshot: %w", err)
	}
	total.SnapshotID = dirResult.SnapshotID
	total.KeyFingerprint = dirResult.KeyFingerprint
	total.BytesScanned += dirResult.BytesScanned
	total.BytesUploaded += dirResult.BytesUploaded
	total.ChunkCount = dirResult.ChunkCount
	total.Duration = now().Sub(started)
	if total.BytesUploaded > 0 {
		total.DedupRatio = float64(total.BytesScanned) / float64(total.BytesUploaded)
	}
	total.Details = rundetail.WrapManifest(rundetail.TypeM365, data)

	if failed > 0 {
		var msgs []string
		for _, r := range results {
			if r.Status == "failed" {
				msgs = append(msgs, r.Name+": "+r.Error)
			}
		}
		msg := fmt.Sprintf("%d of %d units failed: %s", failed, len(units), truncate(strings.Join(msgs, "; "), 8<<10))
		if failed == len(units) {
			total.Status = "failed"
			total.ErrorMessage = msg
			return total, errors.New(msg)
		}
		total.ErrorMessage = "completed with " + msg
		slog.Warn("Microsoft 365 backup completed with failed units", "failed", failed, "units", len(units))
	}
	return total, nil
}

// selectUnits resolves users, sites and teams into units with unique groups
func selectUnits(ctx context.Context, c *Client, s *spec.Spec, jobGroup string, warn func(string, ...any)) ([]Unit, error) {
	var units []Unit
	teamSites := map[string]bool{}
	if s.Workloads.EffTeams() {
		teams, err := SelectTeams(ctx, c, s.Teams)
		if err != nil {
			return nil, err
		}
		for i := range teams {
			t := teams[i]
			if siteID, err := teamSiteID(ctx, c, t.ID); err == nil {
				teamSites[siteID] = true
			}
			units = append(units, Unit{Kind: spec.UnitTeam, Name: t.DisplayName, ObjectID: t.ID, Archive: ArchiveTeam, Team: &t})
		}
	}
	if s.Workloads.EffMailboxes() || s.Workloads.EffOneDrive() {
		users, warnings, err := SelectUsers(ctx, c, s.Users)
		if err != nil {
			return nil, err
		}
		for _, w := range warnings {
			warn("%s", w)
		}
		for i := range users {
			u := users[i]
			units = append(units, Unit{Kind: spec.UnitUser, Name: u.UPN, ObjectID: u.ID, Archive: ArchiveUser, Principal: &u})
		}
	}
	if s.Workloads.EffSites() {
		sites, err := SelectSites(ctx, c, s.Sites, teamSites)
		if err != nil {
			return nil, err
		}
		for i := range sites {
			st := sites[i]
			units = append(units, Unit{Kind: spec.UnitSite, Name: siteKey(st.WebURL), ObjectID: st.ID, Archive: ArchiveSite, Site: &st})
		}
	}
	// Group names: <job group>-<kind>-<safe name>, a short object-id tag on collision
	seen := map[string]bool{}
	for i := range units {
		g := spec.UnitGroup(jobGroup, units[i].Kind, units[i].Name)
		if seen[g] {
			g += "-" + shortID(units[i].ObjectID)[:4]
		}
		seen[g] = true
		units[i].Group = g
	}
	sort.SliceStable(units, func(i, j int) bool { return units[i].Group < units[j].Group })
	return units, nil
}

// backupUnit produces one unit snapshot; it never returns an error, the outcome is
// the UnitResult (one failing user must not fail the tenant)
func backupUnit(ctx context.Context, c *Client, s *spec.Spec, state State, o RunOptions, u *Unit, now func() time.Time, warnRun func(string, ...any)) spec.UnitResult {
	res := spec.UnitResult{Kind: u.Kind, Name: u.Name, ObjectID: u.ObjectID, Group: u.Group, Status: "completed"}
	fail := func(err error) spec.UnitResult {
		if ctx.Err() != nil {
			res.Status, res.Error = "cancelled", "cancelled"
			return res
		}
		res.Status, res.Error = "failed", err.Error()
		slog.Error("Microsoft 365 unit failed", "kind", u.Kind, "unit", u.Name, "error", err)
		return res
	}
	warn := func(msg string) { res.Warnings = append(res.Warnings, msg) }

	idx, err := state.Load(u.Group)
	if err != nil {
		return fail(fmt.Errorf("loading index: %w", err))
	}
	idx.Kind, idx.Name, idx.ObjectID = u.Kind, u.Name, u.ObjectID
	if idx.LastRunID == o.Session.BackupRunID.String() && idx.LastStatus == "completed" {
		res.SnapshotTime = idx.LastSnapshot
		res.Warnings = append(res.Warnings, "finished by an earlier attempt of this run")
		return res
	}

	spool := filepath.Join(o.SpoolDir, o.Session.BackupRunID.String(), spec.SafeName(u.Group))
	defer os.RemoveAll(spool) //nolint:errcheck

	var entries []Entry
	var dirs []Dir
	addDrives := func(refs []driveRef) error {
		if idx.Drives == nil {
			idx.Drives = map[string]*DriveIndex{}
		}
		live := map[string]bool{}
		excludes, _ := scan.ParsePatterns(s.ExcludePaths)
		for _, ref := range refs {
			live[ref.ID] = true
			di := idx.Drives[ref.ID]
			if di == nil {
				di = &DriveIndex{ID: ref.ID}
				idx.Drives[ref.ID] = di
			}
			di.Name, di.WebURL, di.Prefix = ref.Name, ref.WebURL, ref.Prefix
			e, d, st, err := collectDrive(ctx, c, di, excludes, now(), func(w string) { warn(ref.Prefix + ": " + w) })
			if err != nil {
				return fmt.Errorf("%s: %w", ref.Prefix, err)
			}
			entries, dirs = append(entries, e...), append(dirs, d...)
			res.Resyncs += st.Resyncs
			res.Archives = append(res.Archives, spec.ArchiveStats{Name: ref.Prefix, Items: st.Files, Bytes: st.Bytes})
		}
		for id := range idx.Drives {
			if !live[id] {
				delete(idx.Drives, id)
			}
		}
		return nil
	}

	switch u.Kind {
	case spec.UnitUser:
		if s.Workloads.EffMailboxes() {
			if idx.Mailbox == nil {
				idx.Mailbox = &MailboxIndex{}
			}
			mc := &mailboxCollector{c: c, spec: s, spool: spool, userID: u.ObjectID, idx: idx.Mailbox, now: now(), warn: func(w string) { warn("mailbox: " + w) }}
			e, d, err := mc.collect(ctx)
			if err != nil {
				return fail(fmt.Errorf("mailbox: %w", err))
			}
			entries, dirs = append(entries, e...), append(dirs, d...)
			res.Resyncs += mc.stats.Resyncs
			res.Archives = append(res.Archives, spec.ArchiveStats{Name: mailboxPrefix, Items: mc.stats.Items, Downloaded: mc.stats.ExportedBytes})
		}
		if s.Workloads.EffOneDrive() {
			ref, err := userDrive(ctx, c, u.ObjectID)
			if err != nil {
				return fail(err)
			}
			var refs []driveRef
			if ref != nil {
				refs = append(refs, *ref)
			} else {
				warn("no OneDrive provisioned")
			}
			if err := addDrives(refs); err != nil {
				return fail(err)
			}
		}
	case spec.UnitSite:
		refs, err := siteDrives(ctx, c, u.ObjectID)
		if err != nil {
			return fail(err)
		}
		if err := addDrives(refs); err != nil {
			return fail(err)
		}
	case spec.UnitTeam:
		if idx.Teams == nil {
			idx.Teams = &TeamsIndex{}
		}
		e, st, err := collectTeam(ctx, c, u.ObjectID, idx.Teams, now(), warn)
		if err != nil {
			return fail(err)
		}
		entries = append(entries, e...)
		res.Archives = append(res.Archives, spec.ArchiveStats{Name: "messages", Items: st.Messages})
		if tj, err := teamJSON(ctx, c, u.ObjectID); err == nil {
			entries = append(entries, memEntry("team.json", tj, now()))
		}
		if s.Workloads.EffSites() || s.Workloads.EffOneDrive() {
			if siteID, err := teamSiteID(ctx, c, u.ObjectID); err == nil {
				refs, err := siteDrives(ctx, c, siteID)
				if err != nil {
					return fail(err)
				}
				if err := addDrives(refs); err != nil {
					return fail(err)
				}
			} else {
				warn("team site not found: " + err.Error())
			}
		}
	}
	if len(entries) == 0 {
		res.Status = "skipped"
		res.Error = "nothing to archive"
		if len(res.Warnings) > 0 {
			res.Error += " (" + strings.Join(res.Warnings, "; ") + ")"
		}
		return res
	}
	unitManifest, _ := json.MarshalIndent(res, "", "  ")
	entries = append(entries, memEntry(spec.UnitManifestName, unitManifest, now()))
	tree, err := BuildTree(u.Archive, entries, dirs, now())
	if err != nil {
		return fail(fmt.Errorf("building the archive tree: %w", err))
	}
	result, err := o.Upload(ctx, u, tree, []gopbs.Blob{{Name: spec.UnitManifestName, Data: unitManifest}})
	if err != nil {
		return fail(err)
	}
	if t, ok := snapshotTime(result.SnapshotID); ok {
		res.SnapshotTime = t
	}
	for i := range res.Archives {
		if res.Archives[i].Bytes == 0 {
			res.Archives[i].Bytes = uint64(result.BytesScanned)
		}
	}
	idx.LastRunID, idx.LastStatus, idx.LastSnapshot = o.Session.BackupRunID.String(), "completed", res.SnapshotTime
	if err := state.Save(idx); err != nil {
		warnRun("%s: index not saved (the next run repeats the delta round): %v", u.Name, err)
	}
	return res
}

// snapshotTime parses the time of "host/<group>/<RFC3339>"
func snapshotTime(snapshot string) (int64, bool) {
	i := strings.LastIndexByte(snapshot, '/')
	if i < 0 {
		return 0, false
	}
	t, err := time.Parse("2006-01-02T15:04:05Z", snapshot[i+1:])
	if err != nil {
		return 0, false
	}
	return t.Unix(), true
}

func restoreNotes(backupType, group string) map[string]string {
	return map[string]string{
		"mailbox":  "Items are Exchange export streams (.exoitem, opaque). Import them into a mailbox with the Graph mailbox import API: POST /admin/exchange/mailboxes/{mailbox}/createImportSession, then POST the stream to the returned importUrl (permission MailboxItem.ImportExport.All). index.json in each folder lists subject, sender and date per file.",
		"onedrive": "Files are stored as they were; restore with PBS file restore or proxmox-backup-client restore and upload them to OneDrive or SharePoint. .fallbck/items.json carries ids, authors and web URLs.",
		"files":    "Document libraries live under files/<library>/; same as OneDrive.",
		"teams":    "Channel messages are JSON per channel and month (messages/<channel>/<yyyy-mm>.json); Graph has no import for channel messages. Inline images are under hosted/.",
		"entra":    "Directory objects are JSON for reference; recreate them by hand or with Graph.",
		"snapshot": fmt.Sprintf("proxmox-backup-client restore %s/<unit group>/<time> <archive>.pxar ./out   # unit groups are listed under units[]; the directory is %s/%s", backupType, backupType, group),
	}
}

func restoreReadme(m *spec.Manifest) string {
	var b strings.Builder
	b.WriteString("# Restoring this Microsoft 365 backup\n\n")
	for _, k := range sortedKeys(m.Restore) {
		b.WriteString("## ")
		b.WriteString(k)
		b.WriteString("\n\n")
		b.WriteString(m.Restore[k])
		b.WriteString("\n\n")
	}
	b.WriteString("## Units\n\n")
	for _, u := range m.Units {
		b.WriteString(fmt.Sprintf("- %s %s → group %s (%s)\n", u.Kind, u.Name, u.Group, u.Status))
	}
	return b.String()
}
