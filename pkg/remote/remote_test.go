package remote

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// testKeys returns an SSH host public key line and an unencrypted private key PEM
func testKeys(t *testing.T) (hostKey, keyPEM string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return sp.Type() + " " + base64.StdEncoding.EncodeToString(sp.Marshal()), string(pem.EncodeToMemory(block))
}

func TestRemoteValidate(t *testing.T) {
	hostKey, keyPEM := testKeys(t)
	ok := map[string]struct {
		in       Remote
		identity string
	}{
		"aws": {Remote{Name: "AWS", Backend: "S3", Region: "eu-north-1",
			Secrets: Secrets{AccessKeyID: "AKIA", SecretAccessKey: "s"}}, "https://s3.amazonaws.com"},
		"minio": {Remote{Name: "minio", Backend: "s3", Endpoint: "HTTP://Minio.Local:9000/", PathStyle: true,
			Secrets: Secrets{AccessKeyID: "a", SecretAccessKey: "s"}}, "http://minio.local:9000"},
		"r2 default port dropped": {Remote{Name: "r2", Backend: "s3", Provider: "cloudflare", Endpoint: "https://x.r2.cloudflarestorage.com:443",
			Secrets: Secrets{AccessKeyID: "a", SecretAccessKey: "s"}}, "https://x.r2.cloudflarestorage.com"},
		"azure key": {Remote{Name: "az", Backend: "azureblob", Account: "Contosodata",
			Secrets: Secrets{AccountKey: "k"}}, "https://contosodata.blob.core.windows.net"},
		"azure sas": {Remote{Name: "az", Backend: "azureblob", Account: "contosodata",
			Secrets: Secrets{SASURL: "https://contosodata.blob.core.windows.net/?sv=2024&sig=x"}}, "https://contosodata.blob.core.windows.net"},
		"azurite": {Remote{Name: "az", Backend: "azureblob", Account: "devstoreaccount1", Endpoint: "http://127.0.0.1:10000",
			Secrets: Secrets{AccountKey: "k"}}, "http://127.0.0.1:10000"},
		"sftp key": {Remote{Name: "nas", Backend: "sftp", Host: "NAS.example.com", User: "backup",
			KnownHosts: []string{"nas.example.com " + hostKey}, Secrets: Secrets{KeyPEM: keyPEM}}, "sftp://nas.example.com:22"},
		"sftp ipv6": {Remote{Name: "nas", Backend: "sftp", Host: "[2001:db8::1]", Port: 2222, User: "b",
			KnownHosts: []string{hostKey}, Secrets: Secrets{Password: "p"}}, "sftp://[2001:db8::1]:2222"},
		"smb": {Remote{Name: "files", Backend: "smb", Host: "fs01", User: "svc", Domain: "CORP",
			Secrets: Secrets{Password: "p"}}, "smb://fs01:445"},
		"webdav anonymous": {Remote{Name: "dav", Backend: "webdav", URL: "https://Cloud.example.com/remote.php/dav/files/alice/"}, "https://cloud.example.com"},
		"agent-held": {Remote{Name: "a", Backend: "s3", AuthMethod: "Agent",
			Secrets: Secrets{AccessKeyID: "dropped", SecretAccessKey: "dropped"}}, "https://s3.amazonaws.com"},
	}
	for name, c := range ok {
		r := c.in
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := r.Identity(); got != c.identity {
			t.Errorf("%s: identity %q, want %q", name, got, c.identity)
		}
	}

	// Fields of other backends and an agent-held remote's secrets are cleared
	r := Remote{Name: "x", Backend: "smb", Host: "fs01", URL: "https://x", Account: "acct", KnownHosts: []string{hostKey},
		Secrets: Secrets{Password: "p", AccessKeyID: "a", BearerToken: "t"}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if r.URL != "" || r.Account != "" || r.KnownHosts != nil || r.Secrets != (Secrets{Password: "p"}) || !r.HasSecret {
		t.Errorf("foreign fields kept: %+v", r)
	}
	r = ok["agent-held"].in
	_ = r.Validate()
	if !r.Secrets.IsZero() || r.HasSecret || r.AuthMethod != AuthAgent {
		t.Errorf("agent-held remote kept a secret: %+v", r)
	}
	// Known host lines are normalised to "<type> <base64>"
	r = ok["sftp key"].in
	_ = r.Validate()
	if !slices.Equal(r.KnownHosts, []string{hostKey}) {
		t.Errorf("known hosts %v", r.KnownHosts)
	}

	bad := map[string]Remote{
		"no name":            {Backend: "s3", Secrets: Secrets{AccessKeyID: "a", SecretAccessKey: "s"}},
		"unknown backend":    {Name: "x", Backend: "gcs"},
		"bad auth method":    {Name: "x", Backend: "s3", AuthMethod: "magic"},
		"no credential":      {Name: "x", Backend: "s3"},
		"half an s3 key":     {Name: "x", Backend: "s3", Secrets: Secrets{AccessKeyID: "a"}},
		"aws with endpoint":  {Name: "x", Backend: "s3", Provider: "AWS", Endpoint: "https://e", Secrets: Secrets{AccessKeyID: "a", SecretAccessKey: "s"}},
		"minio w/o endpoint": {Name: "x", Backend: "s3", Provider: "Minio", Secrets: Secrets{AccessKeyID: "a", SecretAccessKey: "s"}},
		"endpoint with path": {Name: "x", Backend: "s3", Endpoint: "https://e/bucket", Secrets: Secrets{AccessKeyID: "a", SecretAccessKey: "s"}},
		"endpoint creds":     {Name: "x", Backend: "s3", Endpoint: "https://u:p@e", Secrets: Secrets{AccessKeyID: "a", SecretAccessKey: "s"}},
		"ftp scheme":         {Name: "x", Backend: "webdav", URL: "ftp://e"},
		"bad account":        {Name: "x", Backend: "azureblob", Account: "has-dash", Secrets: Secrets{AccountKey: "k"}},
		"sas elsewhere":      {Name: "x", Backend: "azureblob", Account: "contoso", Secrets: Secrets{SASURL: "https://evil.blob.core.windows.net/?sig=x"}},
		"sas without token":  {Name: "x", Backend: "azureblob", Account: "contoso", Secrets: Secrets{SASURL: "https://contoso.blob.core.windows.net/"}},
		"key and sas":        {Name: "x", Backend: "azureblob", Account: "contoso", Secrets: Secrets{AccountKey: "k", SASURL: "https://contoso.blob.core.windows.net/?sig=x"}},
		"sftp no host key":   {Name: "x", Backend: "sftp", Host: "h", User: "u", Secrets: Secrets{Password: "p"}},
		"sftp bad host key":  {Name: "x", Backend: "sftp", Host: "h", User: "u", KnownHosts: []string{"ssh-ed25519 notbase64"}, Secrets: Secrets{Password: "p"}},
		"sftp revoked line":  {Name: "x", Backend: "sftp", Host: "h", User: "u", KnownHosts: []string{"@revoked h " + hostKey}, Secrets: Secrets{Password: "p"}},
		"sftp no user":       {Name: "x", Backend: "sftp", Host: "h", KnownHosts: []string{hostKey}, Secrets: Secrets{Password: "p"}},
		"sftp bad key":       {Name: "x", Backend: "sftp", Host: "h", User: "u", KnownHosts: []string{hostKey}, Secrets: Secrets{KeyPEM: "nope"}},
		"sftp key and pass":  {Name: "x", Backend: "sftp", Host: "h", User: "u", KnownHosts: []string{hostKey}, Secrets: Secrets{KeyPEM: keyPEM, Password: "p"}},
		"host with port":     {Name: "x", Backend: "smb", Host: "fs01:445", Secrets: Secrets{Password: "p"}},
		"port range":         {Name: "x", Backend: "smb", Host: "fs01", Port: 70000, Secrets: Secrets{Password: "p"}},
		"bad vendor":         {Name: "x", Backend: "webdav", URL: "https://e", Vendor: "dropbox"},
		"dav pass and token": {Name: "x", Backend: "webdav", URL: "https://e", Secrets: Secrets{Password: "p", BearerToken: "t"}},
	}
	for name, r := range bad {
		if err := r.Validate(); !errors.Is(err, ErrInvalidRemote) {
			t.Errorf("%s: %v, want ErrInvalidRemote", name, err)
		}
	}
}

func TestCleanHostKeys(t *testing.T) {
	hostKey, _ := testKeys(t)
	got, err := CleanHostKeys([]string{"# nas\n[nas]:2222 " + hostKey + "\n\n" + hostKey + " comment", hostKey})
	if err != nil || !slices.Equal(got, []string{hostKey}) {
		t.Errorf("CleanHostKeys: %v %v", got, err)
	}
}

func TestSpecValidate(t *testing.T) {
	id := uuid.New()
	s := Spec{RemoteID: id, Roots: []string{" /photos/2024/ ", "archive"}, Include: []string{" *.jpg ", ""}, Split: " Per_Root ", Profile: " Prod-S3 "}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.Roots, []string{"photos/2024", "archive"}) || !slices.Equal(s.Include, []string{"*.jpg"}) ||
		s.Split != SplitPerRoot || s.Profile != "prod-s3" || s.EffConcurrency() != DefaultConcurrency {
		t.Errorf("normalised %+v", s)
	}
	if s := (Spec{RemoteID: id}); s.Validate() != nil || s.Split != SplitSingle {
		t.Errorf("default split: %+v", s)
	}

	bad := map[string]Spec{
		"no remote":        {Roots: []string{"b"}},
		"dot segment":      {RemoteID: id, Roots: []string{"b/../c"}},
		"empty segment":    {RemoteID: id, Roots: []string{"b//c"}},
		"duplicate":        {RemoteID: id, Roots: []string{"b", "/b/"}},
		"nested":           {RemoteID: id, Roots: []string{"b/x", "b"}},
		"whole and part":   {RemoteID: id, Roots: []string{"", "b"}},
		"bad glob":         {RemoteID: id, Exclude: []string{"[a"}},
		"bad split":        {RemoteID: id, Split: "per_file"},
		"concurrency":      {RemoteID: id, Concurrency: MaxConcurrency + 1},
		"backup id":        {RemoteID: id, BackupID: "has space"},
		"profile":          {RemoteID: id, Profile: "no spaces"},
		"per-root clashes": {RemoteID: id, Roots: []string{"a/b", "a-b"}, Split: SplitPerRoot},
		"per-root case":    {RemoteID: id, Roots: []string{"Data", "data"}, Split: SplitPerRoot},
	}
	for name, s := range bad {
		if err := s.Validate(); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("%s: %v, want ErrInvalidSpec", name, err)
		}
	}
	// The same clash is fine in one snapshot: the roots are distinct directories
	if s := (Spec{RemoteID: id, Roots: []string{"a/b", "a-b"}}); s.Validate() != nil {
		t.Error("single split refused distinct roots")
	}
}

func TestSpecValidateFor(t *testing.T) {
	id := uuid.New()
	s3 := &Remote{Backend: BackendS3, AuthMethod: AuthStored}
	cases := []struct {
		name  string
		spec  Spec
		r     *Remote
		valid bool
	}{
		{"bucket", Spec{RemoteID: id, Roots: []string{"my-bucket/logs"}}, s3, true},
		{"no bucket: every bucket", Spec{RemoteID: id}, s3, true},
		{"bad bucket", Spec{RemoteID: id, Roots: []string{"My_Bucket"}}, s3, false},
		{"bad container", Spec{RemoteID: id, Roots: []string{"a.b"}}, &Remote{Backend: BackendAzure}, false},
		{"container", Spec{RemoteID: id, Roots: []string{"backups"}}, &Remote{Backend: BackendAzure}, true},
		{"share", Spec{RemoteID: id, Roots: []string{"Data$/x"}}, &Remote{Backend: BackendSMB}, true},
		{"no share: every share", Spec{RemoteID: id}, &Remote{Backend: BackendSMB}, true},
		{"agent-held needs profile", Spec{RemoteID: id, Roots: []string{"bkt"}}, &Remote{Backend: BackendS3, AuthMethod: AuthAgent}, false},
		{"agent-held with profile", Spec{RemoteID: id, Roots: []string{"bkt"}, Profile: "p"}, &Remote{Backend: BackendS3, AuthMethod: AuthAgent}, true},
		{"missing remote", Spec{RemoteID: id}, nil, false},
	}
	for _, c := range cases {
		s := c.spec
		if err := s.Validate(); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if err := s.ValidateFor(c.r); (err == nil) != c.valid {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// SFTP and WebDAV without roots back up the whole remote
	s := Spec{RemoteID: id}
	_ = s.Validate()
	if err := s.ValidateFor(&Remote{Backend: BackendSFTP}); err != nil || !slices.Equal(s.Roots, []string{""}) {
		t.Errorf("whole remote: %v %v", s.Roots, err)
	}
}

func TestGroups(t *testing.T) {
	job := DefaultBackupID("Prod Data (S3)")
	if job != "remote-prod-data-s3" {
		t.Errorf("job group %q", job)
	}
	for root, want := range map[string]string{"photos/2024": "remote-prod-data-s3-photos-2024", "": "remote-prod-data-s3-root", "Data$": "remote-prod-data-s3-data"} {
		if got := UnitGroup(job, root); got != want || !strings.HasPrefix(got, GroupPrefix(job)) {
			t.Errorf("UnitGroup(%q) = %q, want %q", root, got, want)
		}
	}
}

func TestProfile(t *testing.T) {
	hostKey, keyPEM := testKeys(t)
	dir := t.TempDir()
	write := func(name, data string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	secretFile, keyFile := write("secret", "s3cret\n"), write("key", keyPEM)

	ok := map[string]struct {
		p        Profile
		endpoint string
	}{
		"aws":           {Profile{Backend: "s3", Secrets: Secrets{AccessKeyID: "AKIA", SecretAccessKey: "s"}}, "https://s3.amazonaws.com"},
		"aws file":      {Profile{Backend: "s3", Endpoint: "AWS", Secrets: Secrets{AccessKeyID: "AKIA"}, SecretFile: secretFile}, "https://s3.amazonaws.com"},
		"env auth":      {Profile{Backend: "s3", Endpoint: "https://minio:9000/", EnvAuth: true}, "https://minio:9000"},
		"azure account": {Profile{Backend: "azureblob", Endpoint: "Contoso", Secrets: Secrets{AccountKey: "k"}}, "https://contoso.blob.core.windows.net"},
		"azure sas":     {Profile{Backend: "azureblob", Endpoint: "contoso", Secrets: Secrets{SASURL: "https://contoso.blob.core.windows.net/c?sig=x"}}, "https://contoso.blob.core.windows.net"},
		"sftp key file": {Profile{Backend: "sftp", Endpoint: "NAS:2222", KeyFile: keyFile}, "sftp://nas:2222"},
		"sftp default":  {Profile{Backend: "sftp", Endpoint: "nas", Secrets: Secrets{Password: "p"}}, "sftp://nas:22"},
		"smb file":      {Profile{Backend: "smb", Endpoint: "fs01", SecretFile: secretFile}, "smb://fs01:445"},
		"webdav token":  {Profile{Backend: "webdav", Endpoint: "https://cloud.example.com/remote.php/dav", Secrets: Secrets{BearerToken: "t"}}, "https://cloud.example.com"},
	}
	for name, c := range ok {
		p := c.p
		if err := p.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if p.Endpoint != c.endpoint {
			t.Errorf("%s: endpoint %q, want %q", name, p.Endpoint, c.endpoint)
		}
	}
	if p := ok["smb file"].p; p.Validate() == nil {
		if s, err := p.Credentials(); err != nil || s.Password != "s3cret" {
			t.Errorf("secret file: %+v %v", s, err)
		}
		if sum := p.Summary("files"); !sum.Files || sum.Endpoint != "smb://fs01:445" {
			t.Errorf("summary %+v", sum)
		}
	}

	bad := map[string]Profile{
		"no backend":          {Endpoint: "x"},
		"no credential":       {Backend: "smb", Endpoint: "fs01"},
		"two credentials":     {Backend: "smb", Endpoint: "fs01", Secrets: Secrets{Password: "p"}, SecretFile: secretFile},
		"s3 no key id":        {Backend: "s3", Secrets: Secrets{SecretAccessKey: "s"}},
		"s3 secret twice":     {Backend: "s3", Secrets: Secrets{AccessKeyID: "a", SecretAccessKey: "s"}, SecretFile: secretFile},
		"env auth with key":   {Backend: "s3", EnvAuth: true, Secrets: Secrets{AccessKeyID: "a"}},
		"env auth not s3":     {Backend: "smb", Endpoint: "fs01", EnvAuth: true},
		"key file not sftp":   {Backend: "smb", Endpoint: "fs01", KeyFile: keyFile},
		"missing file":        {Backend: "smb", Endpoint: "fs01", SecretFile: filepath.Join(dir, "nope")},
		"key file not a key":  {Backend: "sftp", Endpoint: "nas", KeyFile: secretFile},
		"sas other account":   {Backend: "azureblob", Endpoint: "contoso", Secrets: Secrets{SASURL: "https://evil.blob.core.windows.net/?sig=x"}},
		"bad port":            {Backend: "sftp", Endpoint: "nas:0", Secrets: Secrets{Password: "p"}},
		"azure bad account":   {Backend: "azureblob", Endpoint: "has space", Secrets: Secrets{AccountKey: "k"}},
		"webdav not http url": {Backend: "webdav", Endpoint: "cloud.example.com", Secrets: Secrets{Password: "p"}},
	}
	for name, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	// Matches compares the backend and the remote's identity
	remote := &Remote{Name: "nas", Backend: "sftp", Host: "nas", Port: 2222, User: "b", KnownHosts: []string{hostKey}, Secrets: Secrets{Password: "p"}}
	if err := remote.Validate(); err != nil {
		t.Fatal(err)
	}
	p := ok["sftp key file"].p
	_ = p.Validate()
	if err := p.Matches(remote); err != nil {
		t.Errorf("same endpoint: %v", err)
	}
	remote.Port = 22
	if err := p.Matches(remote); err == nil {
		t.Error("profile matched another port")
	}
	remote.Port, remote.Host = 2222, "evil"
	if err := p.Matches(remote); err == nil {
		t.Error("profile matched another host")
	}
	smb := ok["smb file"].p
	_ = smb.Validate()
	if err := smb.Matches(&Remote{Backend: "sftp", Host: "fs01", Port: 445}); err == nil {
		t.Error("profile matched another backend")
	}
}
