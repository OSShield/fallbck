// Package remote holds the remote storage backup job ("remote": S3, Azure Blob
// and Files, SFTP, SMB, FTP and WebDAV through rclone), the server-side remote model and the agent
// credential profile. It's shared by the server and the agent, so it stays free of
// rclone and agent dependencies.
package remote

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// Backends
const (
	BackendS3     = "s3"
	BackendAzure  = "azureblob"
	BackendSFTP   = "sftp"
	BackendSMB    = "smb"
	BackendWebDAV = "webdav"
	BackendFTP    = "ftp"
	// BackendAzureFiles is Azure Files (SMB shares in a storage account, read
	// through its REST API)
	BackendAzureFiles = "azurefiles"
)

// Backends lists every backend, in display order
var Backends = []string{BackendS3, BackendAzure, BackendAzureFiles, BackendSFTP, BackendSMB, BackendFTP, BackendWebDAV}

// CleanBackends keeps the known backends of an agent's report, without duplicates
func CleanBackends(in []string) []string {
	out := []string{}
	for _, b := range in {
		b = strings.ToLower(strings.TrimSpace(b))
		if slices.Contains(Backends, b) && !slices.Contains(out, b) {
			out = append(out, b)
		}
	}
	return out
}

// Auth methods of a remote
const (
	// AuthStored: the server holds the credential (sealed) and hands it to the agent
	// for each run
	AuthStored = "stored"
	// AuthAgent: the server holds no credential; every job names an agent profile
	AuthAgent = "agent"
)

// S3 providers (the rclone provider setting)
const (
	S3AWS        = "AWS"
	S3Minio      = "Minio"
	S3Wasabi     = "Wasabi"
	S3Cloudflare = "Cloudflare"
	S3Other      = "Other"
)

var s3Providers = []string{S3AWS, S3Minio, S3Wasabi, S3Cloudflare, S3Other}

// FTP TLS modes: explicit (AUTH TLS on the control port) is the default
const (
	FTPTLSExplicit = "explicit"
	FTPTLSImplicit = "implicit"
	FTPTLSNone     = "none"
)

var ftpTLSModes = []string{FTPTLSExplicit, FTPTLSImplicit, FTPTLSNone}

// WebDAV vendors (the rclone vendor setting)
var webdavVendors = []string{"nextcloud", "owncloud", "infinitescale", "sharepoint", "sharepoint-ntlm", "fastmail", "rclone", "other"}

// Remote is a storage endpoint jobs back up from (remotes). Secrets is in clear in
// memory only; the repository seals it with the server master key. Which fields
// apply depends on Backend; Validate clears the others.
type Remote struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	Backend    string    `json:"backend"`
	AuthMethod string    `json:"auth_method"`

	// S3: Provider, Region, Endpoint ("" = AWS) and PathStyle.
	// Azure Blob: Account and Endpoint ("" = <account>.blob.core.windows.net).
	// Azure Files: the same, with <account>.file.core.windows.net.
	Provider  string `json:"provider,omitempty"`
	Region    string `json:"region,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	PathStyle bool   `json:"path_style,omitempty"`
	Account   string `json:"account,omitempty"`

	// SFTP, SMB and FTP: Host, Port (0 = the protocol default) and User. SMB:
	// Domain. FTP: TLS (explicit, implicit or none; the certificate is checked
	// against the system CAs).
	// SFTP: KnownHosts, the server's host keys ("<type> <base64>", required: the
	// agent refuses servers it can't verify).
	Host       string   `json:"host,omitempty"`
	Port       int      `json:"port,omitempty"`
	User       string   `json:"user,omitempty"`
	Domain     string   `json:"domain,omitempty"`
	KnownHosts []string `json:"known_hosts,omitempty"`
	TLS        string   `json:"tls,omitempty"`

	// WebDAV: URL, Vendor and User
	URL    string `json:"url,omitempty"`
	Vendor string `json:"vendor,omitempty"`

	Secrets Secrets `json:"-"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// HasSecret: the server holds a credential. Never the credential itself.
	HasSecret bool `json:"has_secret"`
	Jobs      int  `json:"jobs"`
	// Labels place the remote in access scopes (db.Labels; a plain map here because
	// pkg/db imports this package)
	Labels map[string]string `json:"labels"`
}

// Secrets are the credential fields of every backend. Only the backend's own are
// kept (see Remote.Validate and Profile.Validate).
type Secrets struct {
	// S3
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	// Azure Blob and Files: the account key, or a SAS URL on the remote's own account
	AccountKey string `json:"account_key,omitempty"`
	SASURL     string `json:"sas_url,omitempty"`
	// SFTP, SMB, FTP and WebDAV
	Password string `json:"password,omitempty"`
	// SFTP: an unencrypted private key (PEM or OpenSSH format)
	KeyPEM string `json:"key_pem,omitempty"`
	// WebDAV: instead of a password
	BearerToken string `json:"bearer_token,omitempty"`
}

// IsZero reports whether no credential is set
func (s Secrets) IsZero() bool { return s == Secrets{} }

// ErrInvalidRemote wraps every validation failure
var ErrInvalidRemote = errors.New("invalid remote")

func remoteErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidRemote, fmt.Sprintf(format, args...))
}

// Validate normalises the remote and checks it against its backend. Fields of other
// backends are cleared, and so are the secrets of an AuthAgent remote.
func (r *Remote) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	r.Backend = strings.ToLower(strings.TrimSpace(r.Backend))
	if r.Name == "" {
		return remoteErr("name is required")
	}
	switch m := strings.ToLower(strings.TrimSpace(r.AuthMethod)); m {
	case "", AuthStored:
		r.AuthMethod = AuthStored
	case AuthAgent:
		r.AuthMethod = AuthAgent
	default:
		return remoteErr("auth_method must be %s or %s", AuthStored, AuthAgent)
	}
	r.Region, r.Account = strings.TrimSpace(r.Region), strings.ToLower(strings.TrimSpace(r.Account))
	r.Host, r.User, r.Domain = strings.ToLower(strings.TrimSpace(r.Host)), strings.TrimSpace(r.User), strings.TrimSpace(r.Domain)
	keep := *r
	*r = Remote{ID: keep.ID, Name: keep.Name, Backend: keep.Backend, AuthMethod: keep.AuthMethod,
		CreatedAt: keep.CreatedAt, UpdatedAt: keep.UpdatedAt, Jobs: keep.Jobs, Labels: keep.Labels}

	var err error
	switch r.Backend {
	case BackendS3:
		r.Region, r.PathStyle = keep.Region, keep.PathStyle
		if keep.Endpoint != "" {
			if r.Endpoint, err = normalizeURL(keep.Endpoint, false); err != nil {
				return remoteErr("endpoint: %v", err)
			}
		}
		if r.Provider, err = s3Provider(keep.Provider, r.Endpoint); err != nil {
			return remoteErr("%v", err)
		}
	case BackendAzure, BackendAzureFiles:
		if !accountRe(keep.Account) {
			return remoteErr("account must be the storage account name (3-24 lower-case letters and digits)")
		}
		r.Account = keep.Account
		if keep.Endpoint != "" {
			if r.Endpoint, err = normalizeURL(keep.Endpoint, false); err != nil {
				return remoteErr("endpoint: %v", err)
			}
		}
	case BackendSFTP, BackendSMB, BackendFTP:
		if r.Host, err = cleanHost(keep.Host); err != nil {
			return remoteErr("host: %v", err)
		}
		if keep.Port < 0 || keep.Port > 65535 {
			return remoteErr("port must be between 1 and 65535")
		}
		r.Port, r.User = keep.Port, keep.User
		switch r.Backend {
		case BackendSMB:
			r.Domain = keep.Domain
		case BackendFTP:
			if r.User == "" {
				return remoteErr("user is required")
			}
			r.TLS = strings.ToLower(strings.TrimSpace(keep.TLS))
			if r.TLS == "" {
				r.TLS = FTPTLSExplicit
			}
			if !slices.Contains(ftpTLSModes, r.TLS) {
				return remoteErr("tls must be one of %s", strings.Join(ftpTLSModes, ", "))
			}
		default:
			if r.User == "" {
				return remoteErr("user is required")
			}
			if r.KnownHosts, err = CleanHostKeys(keep.KnownHosts); err != nil {
				return remoteErr("known_hosts: %v", err)
			}
			if len(r.KnownHosts) == 0 {
				return remoteErr("known_hosts is required: the agent only talks to an SFTP server it can verify (get the key with ssh-keyscan -p <port> <host>)")
			}
		}
	case BackendWebDAV:
		if r.URL, err = normalizeURL(keep.URL, true); err != nil {
			return remoteErr("url: %v", err)
		}
		r.User = keep.User
		r.Vendor = strings.ToLower(strings.TrimSpace(keep.Vendor))
		if r.Vendor == "" {
			r.Vendor = "other"
		}
		if !slices.Contains(webdavVendors, r.Vendor) {
			return remoteErr("vendor must be one of %s", strings.Join(webdavVendors, ", "))
		}
	default:
		return remoteErr("backend must be one of %s", strings.Join(Backends, ", "))
	}

	if r.AuthMethod == AuthAgent {
		r.Secrets = Secrets{}
	} else {
		if r.Secrets, err = cleanSecrets(r.Backend, r.Identity(), keep.Secrets); err != nil {
			return remoteErr("%v", err)
		}
		if r.Secrets.IsZero() && r.Backend != BackendWebDAV {
			return remoteErr("the credential is required (or keep it on the agents: auth_method %s)", AuthAgent)
		}
	}
	r.HasSecret = !r.Secrets.IsZero()
	return nil
}

// Sanitize fills the derived fields
func (r *Remote) Sanitize() *Remote {
	r.HasSecret = !r.Secrets.IsZero()
	return r
}

// Identity is where the remote's credential is sent: the S3 endpoint, the Azure
// blob service, the SFTP or SMB server, the WebDAV server. Agent profiles are bound
// to it. Call after Validate.
func (r *Remote) Identity() string {
	switch r.Backend {
	case BackendS3:
		if r.Endpoint == "" {
			return awsIdentity
		}
		return origin(r.Endpoint)
	case BackendAzure, BackendAzureFiles:
		if r.Endpoint == "" {
			return azureService(r.Backend, r.Account)
		}
		return origin(r.Endpoint)
	case BackendSFTP:
		return "sftp://" + net.JoinHostPort(r.Host, strconv.Itoa(r.EffPort()))
	case BackendSMB:
		return "smb://" + net.JoinHostPort(r.Host, strconv.Itoa(r.EffPort()))
	case BackendFTP:
		return "ftp://" + net.JoinHostPort(r.Host, strconv.Itoa(r.EffPort()))
	case BackendWebDAV:
		return origin(r.URL)
	}
	return ""
}

// azureService is an account's default service URL: blob or file
func azureService(backend, account string) string {
	if backend == BackendAzureFiles {
		return "https://" + account + ".file.core.windows.net"
	}
	return "https://" + account + ".blob.core.windows.net"
}

// awsIdentity covers every AWS region: credentials aren't tied to one
const awsIdentity = "https://s3.amazonaws.com"

// EffPort applies the protocol default
func (r *Remote) EffPort() int {
	if r.Port != 0 {
		return r.Port
	}
	switch r.Backend {
	case BackendSMB:
		return 445
	case BackendFTP:
		if r.TLS == FTPTLSImplicit {
			return 990
		}
		return 21
	}
	return 22
}

func s3Provider(p, endpoint string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		if endpoint == "" {
			return S3AWS, nil
		}
		return S3Other, nil
	}
	for _, known := range s3Providers {
		if strings.EqualFold(p, known) {
			if known == S3AWS && endpoint != "" {
				return "", errors.New("the AWS provider takes no endpoint (set the region instead)")
			}
			if known != S3AWS && endpoint == "" {
				return "", fmt.Errorf("the %s provider needs an endpoint", known)
			}
			return known, nil
		}
	}
	return "", fmt.Errorf("provider must be one of %s", strings.Join(s3Providers, ", "))
}

// cleanSecrets keeps the backend's own credential fields and checks their shape.
// identity is the remote's (an Azure SAS URL must point at it).
func cleanSecrets(backend, identity string, in Secrets) (Secrets, error) {
	var s Secrets
	switch backend {
	case BackendS3:
		s.AccessKeyID, s.SecretAccessKey = strings.TrimSpace(in.AccessKeyID), strings.TrimSpace(in.SecretAccessKey)
		if (s.AccessKeyID == "") != (s.SecretAccessKey == "") {
			return s, errors.New("set both the access key id and the secret access key")
		}
	case BackendAzure, BackendAzureFiles:
		s.AccountKey, s.SASURL = strings.TrimSpace(in.AccountKey), strings.TrimSpace(in.SASURL)
		if s.AccountKey != "" && s.SASURL != "" {
			return s, errors.New("set either the account key or a SAS URL")
		}
		if s.SASURL != "" {
			u, err := url.Parse(s.SASURL)
			if err != nil || u.RawQuery == "" || !strings.EqualFold(u.Scheme+"://"+u.Host, identity) {
				return s, fmt.Errorf("the SAS URL must be a %s/... URL with its token", identity)
			}
		}
	case BackendSFTP:
		s.Password, s.KeyPEM = in.Password, strings.TrimSpace(in.KeyPEM)
		if s.Password != "" && s.KeyPEM != "" {
			return s, errors.New("set either a password or a private key")
		}
		if s.KeyPEM != "" {
			if _, err := ssh.ParseRawPrivateKey([]byte(s.KeyPEM)); err != nil {
				return s, fmt.Errorf("private key: %v (it must be unencrypted)", err)
			}
		}
	case BackendSMB, BackendFTP:
		s.Password = in.Password
	case BackendWebDAV:
		s.Password, s.BearerToken = in.Password, strings.TrimSpace(in.BearerToken)
		if s.Password != "" && s.BearerToken != "" {
			return s, errors.New("set either a password or a bearer token")
		}
	}
	return s, nil
}

// CleanHostKeys normalises SSH host keys to "<type> <base64>". It takes that form,
// authorized_keys lines and known_hosts lines (ssh-keyscan output); the host part
// is dropped, since the key is bound to the remote's own host and port. Blank
// lines and comments are skipped; duplicates are dropped.
func CleanHostKeys(lines []string) ([]string, error) {
	out := []string{}
	for _, raw := range lines {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, err := parseHostKey(line)
			if err != nil {
				return nil, err
			}
			norm := key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal())
			if !slices.Contains(out, norm) {
				out = append(out, norm)
			}
		}
	}
	return out, nil
}

func parseHostKey(line string) (ssh.PublicKey, error) {
	if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err == nil {
		return key, nil
	}
	if marker, _, key, _, _, err := ssh.ParseKnownHosts([]byte(line)); err == nil {
		if marker != "" {
			return nil, fmt.Errorf("%q: @%s entries aren't supported", line, marker)
		}
		return key, nil
	}
	return nil, fmt.Errorf("%q is not an SSH host key", line)
}

// normalizeURL checks an http(s) URL without credentials, query or fragment and
// returns it with a lower-case scheme and host and no trailing slash. withPath keeps
// the path (WebDAV); otherwise the URL must have none.
func normalizeURL(raw string, withPath bool) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%q is not a URL", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("only http:// and https:// URLs are supported")
	}
	if u.User != nil {
		return "", errors.New("the URL must not carry credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("the URL takes no query or fragment")
	}
	u.Host = strings.ToLower(u.Host)
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		u.Host = u.Hostname()
	}
	u.Path, u.RawPath = strings.TrimRight(u.Path, "/"), ""
	if !withPath && u.Path != "" {
		return "", errors.New("the URL takes no path")
	}
	return u.String(), nil
}

// origin is scheme://host[:port] of a normalised URL
func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

// cleanHost accepts a host name or an IP address (no port, no brackets)
func cleanHost(h string) (string, error) {
	h = strings.TrimSuffix(strings.Trim(h, "[]"), ".")
	if h == "" {
		return "", errors.New("is required")
	}
	if net.ParseIP(h) != nil {
		return h, nil
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			return "", fmt.Errorf("%q is not a host name or IP address", h)
		}
	}
	return h, nil
}

func accountRe(a string) bool {
	return len(a) >= 3 && len(a) <= 24 && strings.Trim(a, "abcdefghijklmnopqrstuvwxyz0123456789") == ""
}
