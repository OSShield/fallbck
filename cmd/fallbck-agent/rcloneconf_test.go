package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	rcloneconfig "github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/obscure"
	"golang.org/x/crypto/ssh"

	"github.com/osshield/fallbck/pkg/remote"
)

func writeConf(t *testing.T, keyFile string) string {
	t.Helper()
	conf := `# rclone config
[minio]
type = s3
provider = Minio
access_key_id = AKIA1
secret_access_key = s3-secret
endpoint = https://minio.example.com:9000

[aws]
type = s3
provider = AWS
env_auth = true
region = eu-north-1

[blob]
type = azureblob
sas_url = https://photosacct.blob.core.windows.net/photos?sv=2024&sig=abc

[nas]
type = sftp
host = nas.example.com
port = 2222
user = backup
pass = ` + obscure.MustObscure("sftp-pass") + `
key_file = ` + keyFile + `

[share]
type = smb
host = fs01
user = bkp
domain = CORP
pass = ` + obscure.MustObscure("smb-pass") + `

[cloud]
type = webdav
url = https://cloud.example.com/remote.php/dav/files/bkp
vendor = nextcloud
user = bkp
bearer_token = tok

[secret]
type = crypt
remote = minio:photos

[ftp]
type = ftp
host = ftp.example.com

[jump]
type = sftp
host = h
ssh = ssh -J bastion h

[azurite]
type = azureblob
account = devstoreaccount1
key = k
endpoint = http://127.0.0.1:10000/devstoreaccount1

[r2]
type = s3
provider = Cloudflare
access_key_id = x
secret_access_key = y
`
	path := filepath.Join(t.TempDir(), "rclone.conf")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func hostKeyLine(t *testing.T) string {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func noAsk() (string, error) { panic("asked for a password") }

func TestImportRcloneSections(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "id_ed25519")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeConf(t, keyFile)
	cases := map[string]func(p remote.Profile, r *remote.Remote) bool{
		"minio": func(p remote.Profile, r *remote.Remote) bool {
			return p.Secrets.AccessKeyID == "AKIA1" && p.Secrets.SecretAccessKey == "s3-secret" && r.PathStyle && r.Provider == remote.S3Minio
		},
		"aws": func(p remote.Profile, r *remote.Remote) bool {
			return p.EnvAuth && p.Secrets.IsZero() && p.Endpoint == "https://s3.amazonaws.com" && r.Region == "eu-north-1" && !r.PathStyle
		},
		"blob": func(p remote.Profile, r *remote.Remote) bool {
			return r.Account == "photosacct" && strings.HasPrefix(p.Secrets.SASURL, "https://photosacct.")
		},
		"nas": func(p remote.Profile, r *remote.Remote) bool {
			return p.Secrets.Password == "" && p.KeyFile == keyFile && r.Port == 2222 && r.User == "backup"
		},
		"share": func(p remote.Profile, r *remote.Remote) bool {
			return p.Secrets.Password == "smb-pass" && r.Domain == "CORP" && p.Endpoint == "smb://fs01:445"
		},
		"cloud": func(p remote.Profile, r *remote.Remote) bool {
			return p.Secrets.BearerToken == "tok" && r.Vendor == "nextcloud" && p.Endpoint == "https://cloud.example.com"
		},
	}
	for section, check := range cases {
		kv, err := loadRcloneSection(path, section, noAsk)
		if err != nil {
			t.Fatalf("%s: %v", section, err)
		}
		p, r, err := profileFromRclone(section, kv)
		if err != nil {
			t.Fatalf("%s: %v", section, err)
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("%s: profile: %v", section, err)
		}
		if r.Backend == remote.BackendSFTP {
			r.KnownHosts = []string{hostKeyLine(t)}
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("%s: remote: %v", section, err)
		}
		// The remote printed for the server is one the profile is used for
		if err := p.Matches(r); err != nil {
			t.Errorf("%s: %v", section, err)
		}
		if !check(p, r) {
			t.Errorf("%s: profile %+v remote %+v", section, p, r)
		}
	}

	for section, want := range map[string]string{
		"secret":  "wraps another one",
		"ftp":     `type "ftp"`,
		"jump":    "sets ssh",
		"r2":      "has no endpoint",
		"azurite": "has a path",
		"missing": "no section [missing]",
	} {
		kv, err := loadRcloneSection(path, section, noAsk)
		if err == nil {
			_, _, err = profileFromRclone(section, kv)
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", section, want, err)
		}
	}
}

// Flags override the section; another credential source replaces its secret
func TestImportRcloneOverrides(t *testing.T) {
	path := writeConf(t, "/nonexistent")
	p, _, err := importRcloneProfile(path, "minio", remote.Profile{SecretFile: "/run/secrets/s3"})
	if err != nil || p.SecretFile != "/run/secrets/s3" || p.Secrets.SecretAccessKey != "" || p.Secrets.AccessKeyID != "AKIA1" {
		t.Errorf("secret file: %+v %v", p, err)
	}
	if _, _, err := importRcloneProfile(path, "minio", remote.Profile{Backend: "sftp"}); err == nil || !strings.Contains(err.Error(), "is s3") {
		t.Errorf("backend mismatch: %v", err)
	}
}

// An encrypted rclone.conf opens with the prompt or RCLONE_CONFIG_PASS; a wrong
// password is an error, not another prompt
func TestImportRcloneEncrypted(t *testing.T) {
	plain, err := os.ReadFile(writeConf(t, "/k"))
	if err != nil {
		t.Fatal(err)
	}
	if err := rcloneconfig.SetConfigPassword("conf-pass"); err != nil {
		t.Fatal(err)
	}
	var enc bytes.Buffer
	err = rcloneconfig.Encrypt(bytes.NewReader(plain), &enc)
	rcloneconfig.ClearConfigPassword()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rclone.conf")
	if err := os.WriteFile(path, enc.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, _ := rcloneConfEncrypted(path); !ok {
		t.Fatalf("not detected as encrypted:\n%s", enc.String())
	}

	ask := func(pw string) func() (string, error) { return func() (string, error) { return pw, nil } }
	if kv, err := loadRcloneSection(path, "minio", ask("conf-pass")); err != nil || kv["secret_access_key"] != "s3-secret" {
		t.Fatalf("prompted password: %v %v", kv, err)
	}
	done := make(chan error, 1)
	go func() { _, err := loadRcloneSection(path, "minio", ask("wrong")); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a wrong password opened the config")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a wrong password hangs")
	}
	t.Setenv("RCLONE_CONFIG_PASS", "conf-pass")
	if kv, err := loadRcloneSection(path, "share", noAsk); err != nil || kv["user"] != "bkp" {
		t.Fatalf("RCLONE_CONFIG_PASS: %v %v", kv, err)
	}
}
