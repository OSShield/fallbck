//go:build !windows

package dbbackup

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

// configureKill puts the tool in its own process group and terminates the whole
// group on cancellation (WaitDelay escalates to SIGKILL)
func configureKill(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
}

// configureUser makes the tool run as the named OS user (uid, primary gid and, when
// the agent is root, the supplementary groups) with that user's HOME. Files the tool
// opens itself must be reachable by that user; files the agent opens and hands over
// as stdout need not be.
func configureUser(cmd *exec.Cmd, name string) error {
	u, err := user.Lookup(name)
	if err != nil {
		return err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return fmt.Errorf("gid %q: %w", u.Gid, err)
	}
	cred := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), NoSetGroups: true}
	if os.Geteuid() == 0 {
		// setgroups needs CAP_SETGID; without it (tests running as the same user) the
		// child keeps the agent's supplementary groups
		cred.NoSetGroups = false
		if ids, err := u.GroupIds(); err == nil {
			for _, id := range ids {
				if g, err := strconv.ParseUint(id, 10, 32); err == nil {
					cred.Groups = append(cred.Groups, uint32(g))
				}
			}
		}
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = cred
	env := cmd.Env[:0:0]
	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, "HOME=") {
			continue
		}
		env = append(env, kv)
	}
	if u.HomeDir != "" {
		env = append(env, "HOME="+u.HomeDir)
	}
	cmd.Env = env
	return nil
}
