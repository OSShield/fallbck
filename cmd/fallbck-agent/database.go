package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/osshield/fallbck/pkg/agent/credstore"
	"github.com/osshield/fallbck/pkg/agent/runtime"
	"github.com/osshield/fallbck/pkg/config"
	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
	"golang.org/x/term"
)

// databaseCommand implements `fallbck-agent database ...`: credential profiles in the
// encrypted store, and the db_backup settings of agent.yaml, without editing YAML or
// leaving passwords in clear text.
func databaseCommand(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, databaseUsage)
		return errors.New("missing subcommand")
	}
	switch args[0] {
	case "profile":
		return profileCommand(args[1:])
	case "config":
		return dbConfigCommand(args[1:])
	default:
		return fmt.Errorf("unknown database command %q\n%s", args[0], databaseUsage)
	}
}

const databaseUsage = `Usage:
  fallbck-agent database profile create --name <name> --engine <postgres|mysql|mongodb|mssql> [--user <u>] [--password <p> | --password-file <path> | --ask-password] [--host <h>] [--port <n>] [--tls-mode <m>] [--tls-ca <file>]
  fallbck-agent database profile list
  fallbck-agent database profile delete --name <name>
  fallbck-agent database profile import          # move plain-text profiles from agent.yaml into the encrypted store
  fallbck-agent database config <key> [<value>]  # keys: spool_dir, state_dir, min_free_bytes, keep_failed_spool, postgres_bindir, mysql_bindir, mongo_bindir
Every command takes --config <agent.yaml> (default: the enrolled agent's file). Profiles are
encrypted under <data dir>/credentials.key; only their names and engines are reported to the server.`

// agentConfigPath resolves --config or the enrolled default
func agentConfigPath(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if p := runtime.FindDefaultConfig(agent.Type); p != "" {
		return p, nil
	}
	return "", errors.New("no agent configuration found: enroll first, or pass --config <agent.yaml>")
}

// dataDirOf reads the data directory from the configuration file (env overrides apply)
func dataDirOf(configPath string) (string, error) {
	cfg, err := config.LoadAgentConfig(configPath)
	if err != nil {
		return "", err
	}
	if cfg.DataDir == "" {
		return filepath.Dir(configPath), nil
	}
	return cfg.DataDir, nil
}

func profileCommand(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, databaseUsage)
		return errors.New("missing profile subcommand")
	}
	fs := flag.NewFlagSet("profile "+args[0], flag.ContinueOnError)
	configPath := fs.String("config", "", "Path to agent.yaml")
	name := fs.String("name", "", "Profile name (jobs reference it; default profile of an engine is the engine name)")
	engine := fs.String("engine", "", "postgres, mysql, mongodb or mssql")
	user := fs.String("user", "", "Database user")
	password := fs.String("password", "", "Password (prefer --ask-password: this one lands in the shell history)")
	passwordFile := fs.String("password-file", "", "File holding the password (read at run time)")
	askPassword := fs.Bool("ask-password", false, "Prompt for the password without echo")
	host := fs.String("host", "", "Host the profile connects to when the job leaves it blank")
	port := fs.Int("port", 0, "Port when the job leaves it blank")
	tlsMode := fs.String("tls-mode", "", "disable, prefer, require, verify-ca or verify-full")
	tlsCA := fs.String("tls-ca", "", "CA bundle for verify-ca / verify-full")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfgPath, err := agentConfigPath(*configPath)
	if err != nil {
		return err
	}
	dataDir, err := dataDirOf(cfgPath)
	if err != nil {
		return err
	}
	store := credstore.Open(dataDir)

	switch args[0] {
	case "create", "update", "set":
		if *name == "" || *engine == "" {
			return errors.New("--name and --engine are required")
		}
		p := dbspec.CredentialProfile{Engine: *engine, User: *user, Password: *password, PasswordFile: *passwordFile, Host: *host, Port: *port, TLS: dbspec.TLSSpec{Mode: *tlsMode, CAFile: *tlsCA}}
		if *askPassword {
			pw, err := readPassword("Password for " + *name + ": ")
			if err != nil {
				return err
			}
			p.Password = pw
		}
		if p.Password == "" && p.PasswordFile == "" {
			e, _ := dbspec.NormalizeEngine(p.Engine)
			if e != dbspec.EngineMSSQL && e != dbspec.EngineMongoDB {
				fmt.Fprintln(os.Stderr, "note: no password set; only unix-socket peer authentication can work without one")
			}
		}
		if err := store.Put(*name, p); err != nil {
			return err
		}
		fmt.Printf("Profile %q saved to %s (encrypted). The agent reports the new name with its next heartbeat.\n", strings.ToLower(*name), store.Path())
		return nil
	case "list", "ls":
		names, err := store.Names()
		if err != nil {
			return err
		}
		if len(names) == 0 {
			fmt.Println("No profiles in the encrypted store.")
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "NAME\tENGINE\tUSER\tHOST")
		for _, p := range names {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.Name, p.Engine, p.User, p.Host)
		}
		w.Flush()
		// Plain-text profiles that still exist outside the store
		if cfg, err := config.LoadAgentConfig(cfgPath); err == nil && len(cfg.DBBackup.Profiles) > 0 {
			var plain []string
			stored, _ := store.Load()
			for n := range cfg.DBBackup.Profiles {
				if _, ok := stored[n]; !ok {
					plain = append(plain, n)
				}
			}
			if len(plain) > 0 {
				fmt.Printf("\nPlain-text profiles outside the store (agent.yaml or environment): %s\nMove them with: fallbck-agent database profile import\n", strings.Join(plain, ", "))
			}
		}
		return nil
	case "delete", "remove", "rm":
		if *name == "" {
			return errors.New("--name is required")
		}
		if err := store.Delete(*name); err != nil {
			return err
		}
		fmt.Printf("Profile %q removed.\n", strings.ToLower(*name))
		return nil
	case "import":
		return importProfiles(cfgPath, store)
	default:
		return fmt.Errorf("unknown profile command %q\n%s", args[0], databaseUsage)
	}
}

// importProfiles moves the profiles of agent.yaml into the store and strips them from
// the file (environment profiles cannot be edited here; they are reported)
func importProfiles(cfgPath string, store *credstore.Store) error {
	fileCfg, err := config.ReadAgentConfigFile(cfgPath)
	if err != nil {
		return err
	}
	moved := 0
	for name, p := range fileCfg.DBBackup.Profiles {
		if err := store.Put(name, p); err != nil {
			return fmt.Errorf("profile %q: %w", name, err)
		}
		moved++
	}
	if moved > 0 {
		fileCfg.DBBackup.Profiles = nil
		if err := fileCfg.Save(cfgPath); err != nil {
			return fmt.Errorf("profiles were stored but %s could not be rewritten: %w", cfgPath, err)
		}
	}
	fmt.Printf("%d profile(s) moved from %s into %s.\n", moved, cfgPath, store.Path())
	envCfg, err := config.LoadAgentConfig(cfgPath)
	if err == nil && len(envCfg.DBBackup.Profiles) > 0 {
		var env []string
		stored, _ := store.Load()
		for n := range envCfg.DBBackup.Profiles {
			if _, ok := stored[n]; !ok {
				env = append(env, n)
			}
		}
		if len(env) > 0 {
			fmt.Printf("Profiles from the environment (FALLBCK_AGENT_DB_PROFILE_*) are not moved: %s. Create them here and remove the variables.\n", strings.Join(env, ", "))
		}
	}
	return nil
}

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(pw), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// dbConfigCommand shows or sets one db_backup key of agent.yaml
func dbConfigCommand(args []string) error {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	configPath := fs.String("config", "", "Path to agent.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	cfgPath, err := agentConfigPath(*configPath)
	if err != nil {
		return err
	}
	fileCfg, err := config.ReadAgentConfigFile(cfgPath)
	if err != nil {
		return err
	}
	c := &fileCfg.DBBackup
	keys := map[string]struct {
		get func() string
		set func(string) error
	}{
		"spool_dir":         {func() string { return c.SpoolDir }, func(v string) error { c.SpoolDir = v; return nil }},
		"state_dir":         {func() string { return c.StateDir }, func(v string) error { c.StateDir = v; return nil }},
		"min_free_bytes":    {func() string { return strconv.FormatInt(c.MinFreeBytes, 10) }, func(v string) error { n, err := strconv.ParseInt(v, 10, 64); c.MinFreeBytes = n; return err }},
		"keep_failed_spool": {func() string { return strconv.FormatBool(c.KeepFailedSpool) }, func(v string) error { b, err := strconv.ParseBool(v); c.KeepFailedSpool = b; return err }},
		"postgres_bindir":   {func() string { return c.Tools.PostgresBinDir }, func(v string) error { c.Tools.PostgresBinDir = v; return nil }},
		"mysql_bindir":      {func() string { return c.Tools.MySQLBinDir }, func(v string) error { c.Tools.MySQLBinDir = v; return nil }},
		"mongo_bindir":      {func() string { return c.Tools.MongoBinDir }, func(v string) error { c.Tools.MongoBinDir = v; return nil }},
	}
	if len(rest) == 0 {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		for _, k := range []string{"spool_dir", "state_dir", "min_free_bytes", "keep_failed_spool", "postgres_bindir", "mysql_bindir", "mongo_bindir"} {
			v := keys[k].get()
			if v == "" || v == "0" {
				v = "(default)"
			}
			fmt.Fprintf(w, "%s\t%s\n", k, v)
		}
		return w.Flush()
	}
	entry, ok := keys[rest[0]]
	if !ok {
		return fmt.Errorf("unknown key %q (spool_dir, state_dir, min_free_bytes, keep_failed_spool, postgres_bindir, mysql_bindir, mongo_bindir)", rest[0])
	}
	if len(rest) == 1 {
		fmt.Println(entry.get())
		return nil
	}
	value := rest[1]
	if value == "-" || value == "default" {
		value = ""
		if rest[0] == "min_free_bytes" {
			value = "0"
		}
		if rest[0] == "keep_failed_spool" {
			value = "false"
		}
	}
	if err := entry.set(value); err != nil {
		return fmt.Errorf("%s: %w", rest[0], err)
	}
	if err := fileCfg.Save(cfgPath); err != nil {
		return err
	}
	fmt.Printf("%s = %s written to %s (restart the agent to apply).\n", rest[0], cmpOr(entry.get(), "(default)"), cfgPath)
	return nil
}

func cmpOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
