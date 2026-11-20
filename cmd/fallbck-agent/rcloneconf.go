package main

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	rclonefs "github.com/rclone/rclone/fs"
	rcloneconfig "github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configfile"
	"github.com/rclone/rclone/fs/config/obscure"

	"github.com/osshield/fallbck/pkg/remote"
)

// loadRcloneSection reads one section of an rclone.conf with rclone's own config
// code, decrypting an encrypted file with RCLONE_CONFIG_PASS or a password from ask
func loadRcloneSection(path, section string, ask func() (string, error)) (map[string]string, error) {
	if encrypted, err := rcloneConfEncrypted(path); err != nil {
		return nil, err
	} else if encrypted && os.Getenv("RCLONE_CONFIG_PASS") == "" {
		pass, err := ask()
		if err != nil {
			return nil, err
		}
		if err := rcloneconfig.SetConfigPassword(pass); err != nil {
			return nil, err
		}
	}
	// rclone would ask again, forever, after a wrong password
	rclonefs.GetConfig(context.Background()).AskPassword = false
	defer rcloneconfig.ClearConfigPassword()
	if err := rcloneconfig.SetConfigPath(path); err != nil {
		return nil, err
	}
	var st configfile.Storage
	if err := st.Load(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if !st.HasSection(section) {
		return nil, fmt.Errorf("%s has no section [%s] (it has: %s)", path, section, strings.Join(st.GetSectionList(), ", "))
	}
	kv := map[string]string{}
	for _, k := range st.GetKeyList(section) {
		kv[k], _ = st.GetValue(section, k)
	}
	return kv, nil
}

// rcloneConfEncrypted reports whether the first line that isn't blank or a comment
// is rclone's encryption marker
func rcloneConfEncrypted(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
			continue
		}
		return strings.HasPrefix(l, "RCLONE_ENCRYPT_V"), nil
	}
	return false, sc.Err()
}

// rcloneRefused are settings an imported profile can't honour: other ways to
// authenticate, or ones that run commands. A set value refuses the section.
var rcloneRefused = map[string][]string{
	remote.BackendS3:     {"profile", "shared_credentials_file", "session_token", "role_arn"},
	remote.BackendAzure:  {"env_auth", "use_msi", "msi_object_id", "msi_client_id", "msi_mi_res_id", "client_id", "client_secret", "client_certificate_path", "service_principal_file", "use_az", "use_emulator", "connection_string"},
	remote.BackendSFTP:   {"ssh", "key_file_pass", "key_use_agent", "pubkey", "pubkey_file", "ask_password"},
	remote.BackendSMB:    {"use_kerberos", "spn"},
	remote.BackendWebDAV: {"bearer_token_command", "auth_redirect"},
}

// profileFromRclone maps an rclone section to an agent profile and the remote the
// server needs (without its credential: the profile holds it)
func profileFromRclone(section string, kv map[string]string) (remote.Profile, *remote.Remote, error) {
	typ := strings.ToLower(strings.TrimSpace(kv["type"]))
	switch typ {
	case "alias", "crypt", "union", "combine", "chunker", "compress", "hasher", "cache":
		return remote.Profile{}, nil, fmt.Errorf("[%s] is a %s remote, which wraps another one; import the section it points to", section, typ)
	case remote.BackendS3, remote.BackendAzure, remote.BackendSFTP, remote.BackendSMB, remote.BackendWebDAV:
	default:
		return remote.Profile{}, nil, fmt.Errorf("[%s] is type %q; fallbck can import %s", section, kv["type"], strings.Join(remote.Backends, ", "))
	}
	for _, k := range rcloneRefused[typ] {
		if v := strings.TrimSpace(kv[k]); v != "" && !strings.EqualFold(v, "false") {
			return remote.Profile{}, nil, fmt.Errorf("[%s] sets %s, which an agent profile doesn't support; create the profile with flags instead", section, k)
		}
	}
	reveal := func(k string) (string, error) {
		v := kv[k]
		if v == "" {
			return "", nil
		}
		clear, err := obscure.Reveal(v)
		if err != nil {
			return "", fmt.Errorf("[%s] %s: %w", section, k, err)
		}
		return clear, nil
	}
	port := 0
	if p := kv["port"]; p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return remote.Profile{}, nil, fmt.Errorf("[%s] port %q: %w", section, p, err)
		}
		port = n
	}

	p := remote.Profile{Backend: typ}
	r := &remote.Remote{Name: section, Backend: typ, AuthMethod: remote.AuthAgent}
	var err error
	switch typ {
	case remote.BackendS3:
		r.Region, r.Endpoint = kv["region"], kv["endpoint"]
		switch prov := kv["provider"]; prov {
		case "", remote.S3AWS, remote.S3Minio, remote.S3Wasabi, remote.S3Cloudflare:
			r.Provider = prov
		default:
			r.Provider = remote.S3Other
		}
		if r.Endpoint == "" && r.Provider != "" && r.Provider != remote.S3AWS {
			return remote.Profile{}, nil, fmt.Errorf("[%s] has no endpoint; rclone fills one in for %s, fallbck needs it written out", section, r.Provider)
		}
		// rclone's default is path style, except on AWS
		r.PathStyle = r.Endpoint != "" && !strings.EqualFold(kv["force_path_style"], "false")
		p.Endpoint = r.Endpoint
		if strings.EqualFold(kv["env_auth"], "true") {
			p.EnvAuth = true
		} else {
			p.Secrets.AccessKeyID, p.Secrets.SecretAccessKey = kv["access_key_id"], kv["secret_access_key"]
		}
	case remote.BackendAzure:
		r.Account, r.Endpoint = kv["account"], kv["endpoint"]
		if r.Account == "" {
			// a SAS URL names its account: https://<account>.blob.core.windows.net/...
			if host, ok := strings.CutPrefix(kv["sas_url"], "https://"); ok {
				r.Account, _, _ = strings.Cut(host, ".")
			}
		}
		if u, err := url.Parse(r.Endpoint); err == nil && strings.Trim(u.Path, "/") != "" {
			return remote.Profile{}, nil, fmt.Errorf("[%s] endpoint %s has a path (the emulator form, <url>/<account>); fallbck takes the blob service URL without one", section, r.Endpoint)
		}
		p.Endpoint = r.Endpoint
		if p.Endpoint == "" {
			p.Endpoint = r.Account
		}
		p.Secrets.AccountKey, p.Secrets.SASURL = kv["key"], kv["sas_url"]
	case remote.BackendSFTP, remote.BackendSMB:
		r.Host, r.Port, r.User, r.Domain = kv["host"], port, kv["user"], kv["domain"]
		if r.User == "" {
			r.User = os.Getenv("USER") // rclone's default
		}
		p.Endpoint = r.Host
		if port != 0 {
			p.Endpoint += ":" + strconv.Itoa(port)
		}
		if p.Secrets.Password, err = reveal("pass"); err != nil {
			return remote.Profile{}, nil, err
		}
		if typ == remote.BackendSFTP {
			// rclone writes key_pem on one line with \n for the line breaks
			p.Secrets.KeyPEM = strings.ReplaceAll(kv["key_pem"], `\n`, "\n")
			if kf := kv["key_file"]; kf != "" {
				if strings.HasPrefix(kf, "~/") {
					home, _ := os.UserHomeDir()
					kf = filepath.Join(home, kf[2:])
				}
				p.KeyFile = kf
			}
			// rclone tries the key, then the password; a profile holds one: the key
			if p.Secrets.KeyPEM != "" || p.KeyFile != "" {
				p.Secrets.Password = ""
			}
		}
	case remote.BackendWebDAV:
		r.URL, r.User, r.Vendor = kv["url"], kv["user"], kv["vendor"]
		p.Endpoint = r.URL
		if p.Secrets.Password, err = reveal("pass"); err != nil {
			return remote.Profile{}, nil, err
		}
		p.Secrets.BearerToken = kv["bearer_token"]
	}
	return p, r, nil
}

// remoteBody is the remote as a POST /api/v1/remotes body: the settings only
func remoteBody(r *remote.Remote, knownHostsFile string) map[string]any {
	b := map[string]any{"name": r.Name, "backend": r.Backend, "auth_method": r.AuthMethod}
	set := func(k string, v any) {
		switch x := v.(type) {
		case string:
			if x != "" {
				b[k] = x
			}
		case int:
			if x != 0 {
				b[k] = x
			}
		case bool:
			if x {
				b[k] = x
			}
		}
	}
	set("provider", r.Provider)
	set("region", r.Region)
	set("endpoint", r.Endpoint)
	set("path_style", r.PathStyle)
	set("account", r.Account)
	set("host", r.Host)
	set("port", r.Port)
	set("user", r.User)
	set("domain", r.Domain)
	set("url", r.URL)
	set("vendor", r.Vendor)
	if r.Backend == remote.BackendSFTP {
		hint := "ssh-keyscan -p " + strconv.Itoa(r.EffPort()) + " " + r.Host
		if knownHostsFile != "" {
			hint = "the keys for this host in " + knownHostsFile
		}
		b["known_hosts"] = []string{"<" + hint + ">"}
	}
	return b
}
