package runtime

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/osshield/fallbck/pkg/agent/enrollment"
	"github.com/osshield/fallbck/pkg/config"
)

// MigrateDBAgent takes over a fallbck-db-agent installation for the combined agent:
// the binlog/WAL chain state (state/db) is copied into this agent's data directory
// so continuation backups keep their chain, and the credential profiles and tool
// directories from the old agent.yaml are merged into this agent's configuration
// when it has none. Nothing is deleted; the server-side move of the jobs and the
// removal of the old service are printed for the operator.
func MigrateDBAgent(fromDir, cfgPath string) error {
	if cfgPath == "" {
		return errors.New("this agent is not enrolled yet: enroll first, then migrate")
	}
	cfg, err := config.ReadAgentConfigFile(cfgPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", cfgPath, err)
	}
	if cfg.AgentID == "" {
		return fmt.Errorf("%s has no agent id: enroll first, then migrate", cfgPath)
	}
	oldPath := filepath.Join(fromDir, enrollment.ConfigFileName)
	old, err := config.ReadAgentConfigFile(oldPath)
	if err != nil {
		return fmt.Errorf("reading the database agent configuration %s: %w", oldPath, err)
	}
	fmt.Printf("Taking over fallbck-db-agent %s (%s) for fallbck-agent %s\n", old.AgentID, fromDir, cfg.AgentID)

	// Chain state: <old>/state/db → <new>/state/db (existing files win)
	oldState := old.DBBackup.StateDir
	if oldState == "" {
		oldState = filepath.Join(fromDir, "state", "db")
	}
	newState := cfg.DBBackup.StateDir
	if newState == "" {
		newState = filepath.Join(cfg.DataDir, "state", "db")
	}
	copied, err := copyMissing(oldState, newState)
	if err != nil {
		return fmt.Errorf("copying chain state: %w", err)
	}
	fmt.Printf("  chain state: %d file(s) copied from %s to %s\n", copied, oldState, newState)

	// Credential profiles and tool directories
	changed := false
	if len(cfg.DBBackup.Profiles) == 0 && len(old.DBBackup.Profiles) > 0 {
		cfg.DBBackup.Profiles = old.DBBackup.Profiles
		changed = true
		fmt.Printf("  credential profiles: %d moved into %s\n", len(old.DBBackup.Profiles), cfgPath)
	} else if len(old.DBBackup.Profiles) > 0 {
		fmt.Printf("  credential profiles: %s already has profiles, the %d from the database agent were left alone\n", cfgPath, len(old.DBBackup.Profiles))
	}
	empty := config.AgentConfig{}
	if cfg.DBBackup.Tools == empty.DBBackup.Tools && old.DBBackup.Tools != empty.DBBackup.Tools {
		cfg.DBBackup.Tools = old.DBBackup.Tools
		changed = true
		fmt.Println("  tool directories: taken over")
	}
	if changed {
		if err := cfg.Save(cfgPath); err != nil {
			return fmt.Errorf("saving %s: %w", cfgPath, err)
		}
	}
	fmt.Println("\nProfiles set through the environment (FALLBCK_AGENT_DB_PROFILE_* in /etc/fallbck/db-agent.env) must be moved to /etc/fallbck/agent.env by hand.")
	fmt.Println("\nNext, on the server side (moves the jobs and run history, deletes the old agent):")
	fmt.Printf("  fallbck-ctl agents merge %s --into %s\n", old.AgentID, cfg.AgentID)
	fmt.Println("Then retire the old service on this host:")
	fmt.Println("  systemctl disable --now fallbck-db-agent   (OpenRC: rc-service fallbck-db-agent stop; rc-update del fallbck-db-agent)")
	fmt.Println("  apt remove fallbck-db-agent                 (or dnf remove / apk del)")
	return nil
}

// copyMissing copies the files below src into dst that do not exist there yet
func copyMissing(src, dst string) (int, error) {
	if _, err := os.Stat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	n := 0
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if _, err := os.Stat(target); err == nil {
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = out.Close()
			return err
		}
		n++
		return out.Close()
	})
	return n, err
}
