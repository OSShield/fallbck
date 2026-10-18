// Package pbs holds the server's Proxmox Backup Server helpers: API token parsing, key
// files and the token permission check. FallBCK never prunes, forgets or deletes
// anything on PBS, and the API tokens it is given should not carry the privileges to
// (Datastore.Backup only, which EvaluateToken checks). Retention is a PBS datastore
// prune job. Do not add mutating calls.
package pbs

import (
	"slices"
	"sort"
	"strings"
	"time"
)

// PrivBackup is the one privilege a FallBCK target token needs: FallBCK only speaks the
// backup protocol (snapshot notes travel in the manifest, retention is a PBS prune
// job), and Datastore.Backup also reads back the groups the token owns.
const PrivBackup = "Datastore.Backup"

// Token check statuses
const (
	TokenOK      = "ok"      // Datastore.Backup within the target's datastore, nothing else
	TokenExcess  = "excess"  // more than that somewhere
	TokenMissing = "missing" // no Datastore.Backup on the target path: backups fail
	TokenError   = "error"   // the check itself failed
)

// TokenCheck is the stored result of checking a target's API token against PBS
type TokenCheck struct {
	Status    string         `json:"status"`
	Findings  []TokenFinding `json:"findings,omitempty"`
	Error     string         `json:"error,omitempty"`
	TokenID   string         `json:"token_id,omitempty"`
	CheckedAt time.Time      `json:"checked_at"`
	// Permissions is PBS's answer (path → privilege → propagates), kept for the UI
	Permissions map[string]map[string]bool `json:"permissions,omitempty"`
}

// TokenFinding is one path where the token holds more than it should
type TokenFinding struct {
	Path       string   `json:"path"`
	Privileges []string `json:"privileges"`
	Problem    string   `json:"problem"`
}

// Warn reports whether the check should show a warning (anything but ok)
func (c *TokenCheck) Warn() bool { return c != nil && c.Status != TokenOK }

// TargetACLPath is the PBS ACL path a target writes to
func TargetACLPath(datastore, namespace string) string {
	p := "/datastore/" + datastore
	if ns := strings.Trim(namespace, "/"); ns != "" {
		p += "/" + ns
	}
	return p
}

// EvaluateToken judges PBS's answer to GET /access/permissions for the token. all is
// the answer without a path (every path where the token holds something); atTarget
// the answer for the target's own path, which decides whether backups can run at all
// (the target's namespace need not appear in all when it has no ACL entry).
//
// Datastore.Backup anywhere inside the target's datastore is fine: granting it on the
// datastore is the common setup and the token only owns the groups it wrote. Anything
// else, on any path, is excess. A privilege a propagating ancestor already explains
// is reported once, at that ancestor.
func EvaluateToken(all, atTarget map[string]map[string]bool, datastore, namespace string) TokenCheck {
	target := TargetACLPath(datastore, namespace)
	store := TargetACLPath(datastore, "")
	inStore := func(p string) bool { return p == store || strings.HasPrefix(p, store+"/") }

	paths := make([]string, 0, len(all))
	for p := range all {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool {
		return len(paths[i]) < len(paths[j]) || (len(paths[i]) == len(paths[j]) && paths[i] < paths[j])
	})

	// reported[priv] holds the paths where priv was reported and propagates
	reported := map[string][]string{}
	explained := func(p, priv string) bool {
		for _, anc := range reported[priv] {
			if anc == "/" || strings.HasPrefix(p, anc+"/") {
				return true
			}
		}
		return false
	}
	var findings []TokenFinding
	for _, p := range paths {
		var extra []string
		for priv, propagates := range all[p] {
			if priv == PrivBackup && inStore(p) {
				continue
			}
			if explained(p, priv) {
				continue
			}
			extra = append(extra, priv)
			if propagates {
				reported[priv] = append(reported[priv], p)
			}
		}
		if len(extra) == 0 {
			continue
		}
		sort.Strings(extra)
		findings = append(findings, TokenFinding{Path: p, Privileges: extra, Problem: describe(p, extra, store)})
	}

	c := TokenCheck{Status: TokenOK, Findings: findings, Permissions: all}
	if len(findings) > 0 {
		c.Status = TokenExcess
	}
	if _, ok := atTarget[target][PrivBackup]; !ok {
		c.Status = TokenMissing
	}
	return c
}

func describe(path string, privs []string, store string) string {
	reach := "on " + path
	switch {
	case path == "/":
		reach = "on / (everything on this PBS)"
	case path == "/datastore":
		reach = "on /datastore (every datastore)"
	case strings.HasPrefix(path, "/datastore/") && path != store && !strings.HasPrefix(path, store+"/"):
		reach = "on another datastore (" + path + ")"
	}
	if slices.Equal(privs, []string{PrivBackup}) {
		return "Datastore.Backup " + reach + "; the target only needs it on " + store
	}
	return "holds " + strings.Join(privs, ", ") + " " + reach + "; the token needs Datastore.Backup only"
}
