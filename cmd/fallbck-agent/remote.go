package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	libfs "github.com/scheiblingco/librc/fs"
	"golang.org/x/crypto/ssh"

	"github.com/osshield/fallbck/pkg/agent/credstore"
	agentremote "github.com/osshield/fallbck/pkg/agent/remote"
	"github.com/osshield/fallbck/pkg/agent/remote/backends"
	"github.com/osshield/fallbck/pkg/naming"
	"github.com/osshield/fallbck/pkg/remote"
)

// remoteCommand implements `fallbck-agent remote ...`: credential profiles that keep
// a remote storage credential on the agent, so the server never holds it
func remoteCommand(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, remoteUsage)
		return errors.New("missing subcommand")
	}
	switch args[0] {
	case "profile":
		return remoteProfileCommand(args[1:])
	default:
		return fmt.Errorf("unknown remote command %q\n%s", args[0], remoteUsage)
	}
}

const remoteUsage = `Usage:
  fallbck-agent remote profile create --name <name> --backend s3 --endpoint <url|aws> (--access-key-id <id> (--ask-secret | --secret-file <path>) | --env-auth)
  fallbck-agent remote profile create --name <name> --backend azureblob --endpoint <account|url> (--ask-secret | --ask-sas-url | --secret-file <path>)
  fallbck-agent remote profile create --name <name> --backend sftp --endpoint <host[:port]> (--ask-secret | --secret-file <path> | --key-file <pem> [--store-key])
  fallbck-agent remote profile create --name <name> --backend smb --endpoint <host[:port]> (--ask-secret | --secret-file <path>)
  fallbck-agent remote profile create --name <name> --backend webdav --endpoint <url> (--ask-secret | --ask-token | --secret-file <path>)
  fallbck-agent remote profile create --name <name> --from-rclone-conf <rclone.conf> [--section <section>] [flags above to override]
  fallbck-agent remote profile list
  fallbck-agent remote profile delete --name <name>
  fallbck-agent remote profile test --name <name> --root <root> [--user <user>] [--region <region>] [--domain <domain>] [--host-key "<type> <base64>"]
Every command takes --config <agent.yaml> (default: the enrolled agent's file). A job uses a
profile by naming it; the agent uses it only when the profile's backend and endpoint equal the
job's remote, so a changed remote can't send the credential anywhere else. Credentials are
encrypted under <data dir>/credentials.key; only names, backends and endpoints are reported to
the server. --ask-* reads from the terminal without echo, or one line from standard input when
piped. --secret-file holds the S3 secret access key, the Azure account key or the password;
secret and key files are read at every run, and --store-key copies the SFTP key into the
store instead. --env-auth (S3) uses the agent's environment or instance role.
--from-rclone-conf imports an rclone remote of type s3, azureblob, sftp, smb or webdav, including
its obscured password; an encrypted file is opened with RCLONE_CONFIG_PASS or a prompt. The
credential is copied into the store (an SFTP key_file is still read at every run, unless
--store-key), and the matching remote for the server is printed.
test lists the start of a root (S3 bucket, Azure container, SMB share, SFTP or WebDAV path)
with the user, region or domain the remote has. Without --host-key, SFTP prints the server's
host key and trusts it for the test only: compare its fingerprint before adding it to the remote.
`

func remoteProfileCommand(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, remoteUsage)
		return errors.New("missing profile subcommand")
	}
	fs := flag.NewFlagSet("remote profile "+args[0], flag.ContinueOnError)
	configPath := fs.String("config", "", "Path to agent.yaml")
	name := fs.String("name", "", "Profile name (jobs reference it)")
	backend := fs.String("backend", "", strings.Join(remote.Backends, ", "))
	endpoint := fs.String("endpoint", "", "Where the credential may be sent: S3 endpoint URL or aws, Azure account or URL, SFTP/SMB host[:port], WebDAV URL")
	accessKeyID := fs.String("access-key-id", "", "s3: the access key id")
	askSecret := fs.Bool("ask-secret", false, "prompt for the secret access key, account key or password")
	askSAS := fs.Bool("ask-sas-url", false, "azureblob: prompt for a SAS URL instead of the account key")
	askToken := fs.Bool("ask-token", false, "webdav: prompt for a bearer token instead of a password")
	secretFile := fs.String("secret-file", "", "file holding the secret access key, account key or password (read at every run)")
	keyFile := fs.String("key-file", "", "sftp: unencrypted private key (read at every run)")
	storeKey := fs.Bool("store-key", false, "sftp: copy the key into the encrypted store instead of reading the file at every run")
	envAuth := fs.Bool("env-auth", false, "s3: use the agent's environment or instance role (no stored credential)")
	root := fs.String("root", "", "test: the root to list")
	user := fs.String("user", "", "test: the user (sftp, smb, webdav)")
	region := fs.String("region", "", "test: the region (s3)")
	domain := fs.String("domain", "", "test: the domain (smb)")
	hostKey := fs.String("host-key", "", "test: the SFTP server's host key (\"<type> <base64>\")")
	fromConf := fs.String("from-rclone-conf", "", "create: import the backend, endpoint and credential from this rclone.conf")
	section := fs.String("section", "", "create: the rclone.conf section (default: --name)")
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
		if *name == "" || (*backend == "" && *fromConf == "") {
			return errors.New("--name and --backend (or --from-rclone-conf) are required")
		}
		p := remote.Profile{Backend: *backend, Endpoint: *endpoint, SecretFile: *secretFile, KeyFile: *keyFile, EnvAuth: *envAuth,
			Secrets: remote.Secrets{AccessKeyID: *accessKeyID}}
		var imported *remote.Remote
		if *fromConf != "" {
			if *section == "" {
				*section = *name
			}
			if p, imported, err = importRcloneProfile(*fromConf, *section, p); err != nil {
				return err
			}
			*backend = p.Backend
		}
		if *storeKey {
			if p.KeyFile == "" {
				return errors.New("--store-key needs --key-file")
			}
			key, err := os.ReadFile(p.KeyFile)
			if err != nil {
				return err
			}
			p.Secrets.KeyPEM, p.KeyFile = string(key), ""
		}
		var asks int
		for _, a := range []bool{*askSecret, *askSAS, *askToken} {
			if a {
				asks++
			}
		}
		if asks > 1 {
			return errors.New("use one of --ask-secret, --ask-sas-url and --ask-token")
		}
		if asks == 1 {
			v, err := readPassword("Credential for " + *name + ": ")
			if err != nil {
				return err
			}
			switch {
			case *askSAS:
				p.Secrets.SASURL = v
			case *askToken:
				p.Secrets.BearerToken = v
			case strings.EqualFold(*backend, remote.BackendS3):
				p.Secrets.SecretAccessKey = v
			case strings.EqualFold(*backend, remote.BackendAzure):
				p.Secrets.AccountKey = v
			default:
				p.Secrets.Password = v
			}
		}
		if err := store.PutRemote(*name, p); err != nil {
			return err
		}
		n := naming.NormalizeProfileName(*name)
		fmt.Printf("Remote profile %q saved to %s (encrypted). The agent reports it with its next inventory summary.\n", n, store.Path())
		fmt.Println("Check it with: fallbck-agent remote profile test --name " + n + " --root <root>")
		if imported != nil {
			fmt.Println("\nThe matching remote for the server (POST /api/v1/remotes, or the same fields in the web UI):")
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			_ = enc.Encode(remoteBody(imported, ""))
		}
		return nil
	case "list", "ls":
		profiles, err := store.LoadRemote()
		if err != nil {
			return err
		}
		if len(profiles) == 0 {
			fmt.Println("No remote profiles in the encrypted store.")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "NAME\tBACKEND\tENDPOINT\tCREDENTIAL")
		for _, s := range credstore.RemoteSummaries(profiles) {
			p := profiles[s.Name]
			source := "stored"
			switch {
			case p.EnvAuth:
				source = "agent environment"
			case p.SecretFile != "":
				source = "file " + p.SecretFile
			case p.KeyFile != "":
				source = "key file " + p.KeyFile
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Name, s.Backend, s.Endpoint, source)
		}
		return w.Flush()
	case "delete", "remove", "rm":
		if *name == "" {
			return errors.New("--name is required")
		}
		if err := store.DeleteRemote(*name); err != nil {
			return err
		}
		fmt.Printf("Remote profile %q removed.\n", naming.NormalizeProfileName(*name))
		return nil
	case "test":
		if *name == "" {
			return errors.New("--name is required")
		}
		p, err := store.RemoteProfile(*name)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		return testRemoteProfile(ctx, p, *root, *user, *region, *domain, *hostKey)
	default:
		return fmt.Errorf("unknown profile command %q\n%s", args[0], remoteUsage)
	}
}

// importRcloneProfile reads an rclone.conf section into a profile; the flags in
// flagged (backend, endpoint, credential sources) override what the section says
func importRcloneProfile(path, section string, flagged remote.Profile) (remote.Profile, *remote.Remote, error) {
	kv, err := loadRcloneSection(path, section, func() (string, error) { return readPassword("rclone config password: ") })
	if err != nil {
		return remote.Profile{}, nil, err
	}
	p, r, err := profileFromRclone(section, kv)
	if err != nil {
		return remote.Profile{}, nil, err
	}
	if flagged.Backend != "" && !strings.EqualFold(flagged.Backend, p.Backend) {
		return remote.Profile{}, nil, fmt.Errorf("--backend %s, but [%s] is %s", flagged.Backend, section, p.Backend)
	}
	if flagged.Endpoint != "" {
		p.Endpoint = flagged.Endpoint
	}
	if flagged.Secrets.AccessKeyID != "" {
		p.Secrets.AccessKeyID = flagged.Secrets.AccessKeyID
	}
	if flagged.SecretFile != "" || flagged.KeyFile != "" || flagged.EnvAuth {
		// another credential source replaces the section's secret
		p.Secrets = remote.Secrets{AccessKeyID: p.Secrets.AccessKeyID}
		p.SecretFile, p.KeyFile, p.EnvAuth = flagged.SecretFile, flagged.KeyFile, flagged.EnvAuth
	}
	return p, r, nil
}

// testRemoteProfile opens the profile's endpoint as a run would and lists the first
// objects of root
func testRemoteProfile(ctx context.Context, p *remote.Profile, root, user, region, domain, hostKey string) error {
	r, err := profileRemote(ctx, p, user, region, domain, hostKey)
	if err != nil {
		return err
	}
	if err := p.Matches(r); err != nil {
		return err
	}
	secrets, err := p.Credentials()
	if err != nil {
		return err
	}
	sess, err := backends.NewSession(r, agentremote.Credentials{Secrets: secrets, EnvAuth: p.EnvAuth})
	if err != nil {
		return err
	}
	defer sess.Close()
	src, err := sess.Open(ctx, strings.Trim(root, "/"))
	if err != nil {
		return err
	}
	const show = 10
	errEnough := errors.New("enough")
	n := 0
	err = src.Walk(ctx, "", func(e libfs.DirEntry) error {
		if n == show {
			return errEnough
		}
		n++
		if e.IsDir() {
			fmt.Printf("  %s/\n", e.Remote())
		} else {
			fmt.Printf("  %s (%d bytes)\n", e.Remote(), e.Size())
		}
		return nil
	})
	if err != nil && !errors.Is(err, errEnough) {
		return err
	}
	switch {
	case n == 0:
		fmt.Printf("OK: %s %s, root %q is empty.\n", r.Backend, r.Identity(), root)
	case errors.Is(err, errEnough):
		fmt.Printf("OK: %s %s, the first %d entries of root %q.\n", r.Backend, r.Identity(), n, root)
	default:
		fmt.Printf("OK: %s %s, root %q has %d entries.\n", r.Backend, r.Identity(), root, n)
	}
	return nil
}

// profileRemote builds the remote a test talks to from the profile's endpoint and
// the settings the server's remote would carry. Without a host key, an SFTP
// server's key is fetched, printed and trusted for this test only.
func profileRemote(ctx context.Context, p *remote.Profile, user, region, domain, hostKey string) (*remote.Remote, error) {
	r := &remote.Remote{Name: "test", Backend: p.Backend, AuthMethod: remote.AuthAgent, User: user, Region: region, Domain: domain}
	switch p.Backend {
	case remote.BackendS3:
		if p.Endpoint != (&remote.Remote{Backend: remote.BackendS3}).Identity() {
			r.Endpoint, r.PathStyle = p.Endpoint, true
		}
	case remote.BackendAzure:
		host := strings.TrimPrefix(p.Endpoint, "https://")
		if acct, ok := strings.CutSuffix(host, ".blob.core.windows.net"); ok {
			r.Account = acct
		} else {
			// an emulator or private endpoint: http://host:port/<account>
			r.Endpoint = p.Endpoint
			r.Account = user
			if r.Account == "" {
				return nil, errors.New("--user is the storage account name for an Azure endpoint URL")
			}
		}
	case remote.BackendSFTP, remote.BackendSMB:
		hostport := p.Endpoint[strings.Index(p.Endpoint, "://")+3:]
		host, port, err := net.SplitHostPort(hostport)
		if err != nil {
			return nil, err
		}
		r.Host = host
		r.Port, _ = strconv.Atoi(port)
		if p.Backend == remote.BackendSFTP {
			if hostKey == "" {
				if hostKey, err = scanHostKey(ctx, hostport); err != nil {
					return nil, err
				}
			}
			r.KnownHosts = []string{hostKey}
		}
	case remote.BackendWebDAV:
		r.URL = p.Endpoint
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// scanHostKey fetches an SFTP server's host key (like ssh-keyscan) and prints it
func scanHostKey(ctx context.Context, addr string) (string, error) {
	var key ssh.PublicKey
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_, _, _, _ = ssh.NewClientConn(conn, addr, &ssh.ClientConfig{User: "fallbck", Timeout: 15 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = k
			return errors.New("host key fetched")
		}})
	if key == nil {
		return "", fmt.Errorf("could not read the host key of %s", addr)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	fmt.Printf("Host key of %s (trusted for this test only): %s\n  %s\n", addr, ssh.FingerprintSHA256(key), line)
	return line, nil
}
