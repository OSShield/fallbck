package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/osshield/fallbck/pkg/agent/credstore"
	"github.com/osshield/fallbck/pkg/m365"
	"github.com/osshield/fallbck/pkg/naming"
)

// m365Command implements `fallbck-agent m365 ...`: credential profiles that keep the
// app registration's secret or certificate on the agent, so the server never holds it
func m365Command(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, m365Usage)
		return errors.New("missing subcommand")
	}
	switch args[0] {
	case "profile":
		return m365ProfileCommand(args[1:])
	default:
		return fmt.Errorf("unknown m365 command %q\n%s", args[0], m365Usage)
	}
}

const m365Usage = `Usage:
  fallbck-agent m365 profile create --name <name> --tenant-id <id> --client-id <id> (--ask-secret | --secret-file <path>) [--expires YYYY-MM-DD]
  fallbck-agent m365 profile create --name <name> --tenant-id <id> --client-id <id> --auth certificate --cert-file <pem> --key-file <pem> [--store-key]
  fallbck-agent m365 profile list
  fallbck-agent m365 profile delete --name <name>
  fallbck-agent m365 profile test --name <name>   # get a Graph token and read the organization
Every command takes --config <agent.yaml> (default: the enrolled agent's file). A job uses a
profile by naming it; the agent uses it only when its tenant and client ids equal the job's
tenant (write the tenant id the same way in both: GUID or domain). Secrets and keys are
encrypted under <data dir>/credentials.key; only names, ids and expiry dates are reported to
the server. --ask-secret reads from the terminal without echo, or one line from standard input
when piped. Secret and certificate files are read at every run; --store-key copies the
certificate and key into the encrypted store instead.
`

func m365ProfileCommand(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, m365Usage)
		return errors.New("missing profile subcommand")
	}
	fs := flag.NewFlagSet("m365 profile "+args[0], flag.ContinueOnError)
	configPath := fs.String("config", "", "Path to agent.yaml")
	name := fs.String("name", "", "Profile name (jobs reference it)")
	tenantID := fs.String("tenant-id", "", "Directory (tenant) id GUID or verified domain, as on the server's tenant")
	clientID := fs.String("client-id", "", "Application (client) id of the app registration")
	auth := fs.String("auth", "", "secret (default) or certificate")
	askSecret := fs.Bool("ask-secret", false, "secret: prompt for the client secret without echo (or read one line from standard input)")
	secretFile := fs.String("secret-file", "", "secret: file holding the client secret (read at every run)")
	expires := fs.String("expires", "", "secret: when the secret expires (YYYY-MM-DD), so the server can warn")
	certFile := fs.String("cert-file", "", "certificate: the certificate uploaded to the app registration (PEM)")
	keyFile := fs.String("key-file", "", "certificate: its RSA private key (PEM, unencrypted)")
	storeKey := fs.Bool("store-key", false, "certificate: copy the certificate and key into the encrypted store instead of reading the files at every run")
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
		if *name == "" || *tenantID == "" || *clientID == "" {
			return errors.New("--name, --tenant-id and --client-id are required")
		}
		p := m365.Profile{TenantID: *tenantID, ClientID: *clientID, AuthMethod: *auth,
			SecretFile: *secretFile, CertFile: *certFile, KeyFile: *keyFile}
		if *expires != "" {
			t, err := time.Parse(time.DateOnly, *expires)
			if err != nil {
				return errors.New("--expires must be YYYY-MM-DD")
			}
			p.Expires = &t
		}
		if *storeKey {
			if p.CertFile == "" || p.KeyFile == "" {
				return errors.New("--store-key needs --cert-file and --key-file")
			}
			cert, err := os.ReadFile(p.CertFile)
			if err != nil {
				return err
			}
			key, err := os.ReadFile(p.KeyFile)
			if err != nil {
				return err
			}
			p.CertificatePEM, p.KeyPEM, p.CertFile, p.KeyFile = string(cert), string(key), "", ""
		}
		if *askSecret {
			if p.SecretFile != "" {
				return errors.New("use either --ask-secret or --secret-file")
			}
			secret, err := readPassword("Client secret for " + *name + ": ")
			if err != nil {
				return err
			}
			p.Secret = secret
		}
		if err := store.PutM365(*name, p); err != nil {
			return err
		}
		n := naming.NormalizeProfileName(*name)
		fmt.Printf("Microsoft 365 profile %q saved to %s (encrypted). The agent reports it with its next inventory summary.\n", n, store.Path())
		fmt.Println("Check it with: fallbck-agent m365 profile test --name " + n)
		return nil
	case "list", "ls":
		profiles, err := store.LoadM365()
		if err != nil {
			return err
		}
		if len(profiles) == 0 {
			fmt.Println("No Microsoft 365 profiles in the encrypted store.")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "NAME\tTENANT\tCLIENT\tCREDENTIAL\tEXPIRES")
		for _, s := range credstore.M365Summaries(profiles) {
			p := profiles[s.Name]
			source, expires := s.AuthMethod+", stored", "-"
			switch {
			case p.SecretFile != "":
				source = "secret file " + p.SecretFile
			case p.CertFile != "":
				source = "certificate file " + p.CertFile
			}
			if s.Expires != nil {
				expires = s.Expires.Format(time.DateOnly)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.Name, s.TenantID, s.ClientID, source, expires)
		}
		return w.Flush()
	case "delete", "remove", "rm":
		if *name == "" {
			return errors.New("--name is required")
		}
		if err := store.DeleteM365(*name); err != nil {
			return err
		}
		fmt.Printf("Microsoft 365 profile %q removed.\n", naming.NormalizeProfileName(*name))
		return nil
	case "test":
		if *name == "" {
			return errors.New("--name is required")
		}
		p, err := store.M365Profile(*name)
		if err != nil {
			return err
		}
		creds, err := p.Credentials()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		org, err := m365.TestConnection(ctx, creds, "", "")
		if err != nil {
			return err
		}
		fmt.Printf("OK: %s (%s), domains %s\n", org.DisplayName, org.ID, strings.Join(org.Domains, ", "))
		if s := p.Summary(*name); s.Expires != nil {
			fmt.Printf("The %s expires %s.\n", s.AuthMethod, s.Expires.Format(time.DateOnly))
		}
		return nil
	default:
		return fmt.Errorf("unknown profile command %q\n%s", args[0], m365Usage)
	}
}
