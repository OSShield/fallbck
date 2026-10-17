package auth

import (
	"slices"
	"strings"
)

// Permissions are fixed resource:action strings. This table is the only list: the
// router, the role editor and /api/me all read it.
const (
	PermAgentsRead   = "agents:read"
	PermAgentsWrite  = "agents:write" // debug, auto-update, update, inventory, logs, merge, labels
	PermAgentsDelete = "agents:delete"
	PermAgentsEnroll = "agents:enroll" // enrollment tokens

	PermJobsRead   = "jobs:read" // the job and all of its runs
	PermJobsWrite  = "jobs:write"
	PermJobsRun    = "jobs:run" // run, cancel
	PermJobsDelete = "jobs:delete"

	PermTargetsRead        = "targets:read"
	PermTargetsWrite       = "targets:write"
	PermTargetsDelete      = "targets:delete"
	PermTargetsCredentials = "targets:credentials" // reveal the PBS token

	PermKeyringsRead   = "keyrings:read"
	PermKeyringsWrite  = "keyrings:write" // create, rename, master key, rotate, import
	PermKeyringsExport = "keyrings:export"
	PermKeyringsDelete = "keyrings:delete"

	PermTenantsRead   = "tenants:read"
	PermTenantsWrite  = "tenants:write"
	PermTenantsDelete = "tenants:delete"

	PermAPIKeysManage = "apikeys:manage"
	PermRBACManage    = "rbac:manage"
	PermAuditRead     = "audit:read"
	PermTemporalUI    = "temporal:ui"
)

// PermissionGroup is one resource and its actions, for the role editor
type PermissionGroup struct {
	Resource    string   `json:"resource"`
	Permissions []string `json:"permissions"`
}

// Catalog lists every permission grouped by resource, in display order
var Catalog = []PermissionGroup{
	{"agents", []string{PermAgentsRead, PermAgentsWrite, PermAgentsDelete, PermAgentsEnroll}},
	{"jobs", []string{PermJobsRead, PermJobsWrite, PermJobsRun, PermJobsDelete}},
	{"targets", []string{PermTargetsRead, PermTargetsWrite, PermTargetsDelete, PermTargetsCredentials}},
	{"keyrings", []string{PermKeyringsRead, PermKeyringsWrite, PermKeyringsExport, PermKeyringsDelete}},
	{"tenants", []string{PermTenantsRead, PermTenantsWrite, PermTenantsDelete}},
	{"apikeys", []string{PermAPIKeysManage}},
	{"rbac", []string{PermRBACManage}},
	{"audit", []string{PermAuditRead}},
	{"temporal", []string{PermTemporalUI}},
}

// AllPermissions is every permission in catalog order
func AllPermissions() []string {
	var out []string
	for _, g := range Catalog {
		out = append(out, g.Permissions...)
	}
	return out
}

// KnownPermission reports whether p is in the catalog
func KnownPermission(p string) bool { return slices.Contains(AllPermissions(), p) }

// GlobalOnly permissions administer access itself; a binding or API key whose role
// holds one must have an empty selector, otherwise a scoped administrator could grant
// themselves a global role
var GlobalOnly = []string{PermRBACManage, PermAPIKeysManage}

// HasGlobalOnly reports whether a permission set contains a global-only permission
func HasGlobalOnly(perms []string) bool {
	for _, p := range perms {
		if slices.Contains(GlobalOnly, p) {
			return true
		}
	}
	return false
}

// Built-in role names
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

func readPerms() []string {
	var out []string
	for _, p := range AllPermissions() {
		if strings.HasSuffix(p, ":read") {
			out = append(out, p)
		}
	}
	return out
}

// BuiltinRoles are rewritten into the roles table at every start
func BuiltinRoles() map[string][]string {
	viewer := append(readPerms(), PermTemporalUI)
	operator := append(slices.Clone(viewer),
		PermJobsWrite, PermJobsRun, PermJobsDelete,
		PermAgentsWrite, PermAgentsEnroll,
		PermTargetsWrite, PermTenantsWrite)
	return map[string][]string{
		RoleAdmin:    AllPermissions(),
		RoleOperator: operator,
		RoleViewer:   viewer,
	}
}

// BuiltinDescriptions are shown in the Access page
var BuiltinDescriptions = map[string]string{
	RoleAdmin:    "Everything, including access management and API keys",
	RoleOperator: "Read everything; create, run and delete jobs; manage agents, targets and tenants (no deletes of those, no credentials or key export)",
	RoleViewer:   "Read everything and open the Temporal UI",
}
