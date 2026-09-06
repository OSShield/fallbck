//go:build !windows

package dbbackup

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

// isRoot reports whether the agent may switch to other OS users (overridden in tests)
var isRoot = func() bool { return os.Geteuid() == 0 }

// osUserExists checks that the OS user exists (overridden in tests)
var osUserExists = func(name string) error {
	if _, err := user.Lookup(name); err != nil {
		return fmt.Errorf("OS user %q does not exist on this host", name)
	}
	return nil
}

// localMSSQLCredentials: SQL Server on Linux only has SQL logins
func localMSSQLCredentials(spec *dbspec.Spec, creds dbspec.Credentials) (dbspec.Credentials, error) {
	return creds, fmt.Errorf("SQL Server on Linux has no passwordless local login; store a SQL login on the job or in a credential profile")
}

// prepareDirFor creates dir (and parents) for a tool running as the OS user name and
// hands it to that user; the path must already be reachable by that user, which the
// agent's 0700 data directory is not. Tools that write files themselves (pg_basebackup)
// need it; dumps the agent opens and passes as stdout do not.
func prepareDirFor(dir, name string) error {
	u, err := user.Lookup(name)
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	groups := map[int]bool{gid: true}
	if ids, err := u.GroupIds(); err == nil {
		for _, id := range ids {
			if g, err := strconv.Atoi(id); err == nil {
				groups[g] = true
			}
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		return fmt.Errorf("handing %s to %s: %w", dir, name, err)
	}
	// Every ancestor must grant search permission to the user
	for p := filepath.Dir(dir); ; p = filepath.Dir(p) {
		st, err := os.Stat(p)
		if err != nil {
			return err
		}
		if !searchableBy(st, uid, groups) {
			return precheckf(fmt.Sprintf("allow OS user %s to traverse it (chmod o+x %s grants search only, not listing) or point db_backup.spool_dir at a directory %s can reach", name, p, name),
				"spool directory %s is not reachable by OS user %s: %s lacks search permission", dir, name, p)
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}

// searchableBy reports whether the directory grants search (x) to the user: as its
// owner, through one of the user's groups, or to everyone
func searchableBy(st os.FileInfo, uid int, groups map[int]bool) bool {
	if uid == 0 {
		return true
	}
	mode := st.Mode().Perm()
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		if int(sys.Uid) == uid {
			return mode&0o100 != 0
		}
		if groups[int(sys.Gid)] {
			return mode&0o010 != 0
		}
	}
	return mode&0o001 != 0
}
