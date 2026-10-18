// Package tokencheck keeps an eye on the PBS API tokens of backup targets: each one
// should hold Datastore.Backup within its datastore and nothing else. PBS lets a token
// read its own permissions, so the check needs no extra privilege. Anything but ok
// stays on the target as a warning until a later check passes.
package tokencheck

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/pbs"
	"github.com/osshield/fallbck/pkg/proxy"
)

// Interval between scheduled checks of every target
const Interval = 6 * time.Hour

// Check asks PBS about the target's token, stores the result on the target and
// returns it with the previous status ("" when never checked). A failed check is
// stored as status error, never as ok; the returned error is only a storage failure.
func Check(ctx context.Context, d *db.DB, t *db.BackupTarget) (*pbs.TokenCheck, string, error) {
	res := evaluate(ctx, t)
	res.CheckedAt = time.Now().UTC()
	prev, err := d.SetTargetTokenCheck(ctx, t.ID, res)
	if err != nil {
		return nil, "", err
	}
	t.TokenCheck = res
	if prev != res.Status {
		level := slog.LevelWarn
		if res.Status == pbs.TokenOK {
			level = slog.LevelInfo
		}
		slog.Log(ctx, level, "PBS token check of a target changed", "target", t.Name, "target_id", t.ID, "from", prev, "to", res.Status, "token_id", res.TokenID, "error", res.Error)
	}
	return res, prev, nil
}

func evaluate(ctx context.Context, t *db.BackupTarget) *pbs.TokenCheck {
	token, err := pbs.NormalizeAPIToken(t.AuthToken)
	if err != nil {
		return &pbs.TokenCheck{Status: pbs.TokenError, Error: "no usable PBS API token is stored on this target"}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	all, err := proxy.TokenPermissions(ctx, t, "")
	if err != nil {
		return &pbs.TokenCheck{Status: pbs.TokenError, Error: err.Error(), TokenID: pbs.TokenID(token)}
	}
	path := pbs.TargetACLPath(t.Datastore, t.Namespace)
	atTarget, err := proxy.TokenPermissions(ctx, t, path)
	if err != nil {
		return &pbs.TokenCheck{Status: pbs.TokenError, Error: err.Error(), TokenID: pbs.TokenID(token)}
	}
	res := pbs.EvaluateToken(all, atTarget, t.Datastore, t.Namespace)
	res.TokenID = pbs.TokenID(token)
	return &res
}

// ChangeEntry is the audit entry for a status change seen by the scheduled check (no
// request behind it); nil when the status did not change
func ChangeEntry(t *db.BackupTarget, prev string, res *pbs.TokenCheck) *db.AuditEntry {
	if prev == res.Status {
		return nil
	}
	details, _ := json.Marshal(map[string]any{"from": prev, "to": res.Status, "token_id": res.TokenID, "findings": res.Findings, "error": res.Error})
	return &db.AuditEntry{ActorKind: "system", Actor: "fallbck-server", Action: "target.token_check", ResourceKind: "target",
		ResourceID: t.ID.String(), ResourceName: t.Name, Labels: t.Labels, Details: details}
}

// CheckAndAudit runs Check outside a request (scheduled, or after a target was saved)
// and audits a status change as the system
func CheckAndAudit(ctx context.Context, d *db.DB, t *db.BackupTarget) {
	res, prev, err := Check(ctx, d, t)
	if err != nil {
		if !errors.Is(err, db.ErrNotFound) {
			slog.Error("Storing the PBS token check failed", "target", t.Name, "error", err)
		}
		return
	}
	if e := ChangeEntry(t, prev, res); e != nil {
		if err := d.WriteAudit(ctx, e); err != nil {
			slog.Error("Writing the token check audit entry failed", "target", t.Name, "error", err)
		}
	}
}

// Run checks every target a minute after start and then every Interval until ctx ends
func Run(ctx context.Context, d *db.DB) {
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		targets, err := d.ListTargets(ctx, db.Unscoped)
		if err != nil {
			slog.Error("Listing targets for the PBS token check failed", "error", err)
		}
		for _, t := range targets {
			if ctx.Err() != nil {
				return
			}
			CheckAndAudit(ctx, d, t)
		}
		timer.Reset(Interval)
	}
}
