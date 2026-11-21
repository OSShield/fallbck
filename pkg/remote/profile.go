package remote

import (
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Profile is an agent credential profile for remote jobs, kept only in the agent's
// encrypted store. A job names it (Spec.Profile); the agent uses it only when
// Endpoint equals the job's remote identity, so a changed remote can't send the
// credential anywhere else.
type Profile struct {
	Backend string `json:"backend"`
	// Endpoint is the identity of the remote the credential belongs to, in
	// normalised form (see NormalizeEndpoint)
	Endpoint string `json:"endpoint"`
	// Secrets is in clear in memory only; the credential store encrypts it and it's
	// never reported. S3 keeps its access key id here too.
	Secrets Secrets `json:"-"`
	// SecretFile is read at run time instead of the secret: the S3 secret access
	// key, the Azure account key, or the SFTP, SMB, FTP or WebDAV password
	SecretFile string `json:"secret_file,omitempty"`
	// KeyFile is an SFTP private key read at run time
	KeyFile string `json:"key_file,omitempty"`
	// EnvAuth (S3): the credentials come from the agent's environment or instance
	// role, so the profile holds none
	EnvAuth bool `json:"env_auth,omitempty"`
}

// ProfileSummary is what the agent reports about a profile: never the credential
type ProfileSummary struct {
	Name     string `json:"name"`
	Backend  string `json:"backend"`
	Endpoint string `json:"endpoint"`
	Files    bool   `json:"files,omitempty"`
	EnvAuth  bool   `json:"env_auth,omitempty"`
}

// NormalizeEndpoint turns what an administrator writes for a profile into the
// identity it's compared with (Remote.Identity):
//   - S3: the endpoint URL, or "" / "aws" for AWS (any region)
//   - Azure Blob and Files: the account name, or the service URL
//   - SFTP, SMB and FTP: host or host:port (an FTP profile for implicit TLS
//     names port 990)
//   - WebDAV: the server URL (only scheme, host and port count)
func NormalizeEndpoint(backend, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	switch backend {
	case BackendS3:
		if raw == "" || strings.EqualFold(raw, "aws") {
			return awsIdentity, nil
		}
		u, err := normalizeURL(raw, false)
		return origin(u), err
	case BackendAzure, BackendAzureFiles:
		if strings.Contains(raw, "://") {
			u, err := normalizeURL(raw, false)
			return origin(u), err
		}
		if a := strings.ToLower(raw); accountRe(a) {
			return azureService(backend, a), nil
		}
		return "", fmt.Errorf("%q is neither a storage account name nor a URL", raw)
	case BackendSFTP, BackendSMB, BackendFTP:
		host, port := raw, 0
		if h, p, err := net.SplitHostPort(raw); err == nil {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return "", fmt.Errorf("%q has no usable port", raw)
			}
			host, port = h, n
		}
		host, err := cleanHost(strings.ToLower(host))
		if err != nil {
			return "", err
		}
		r := Remote{Backend: backend, Host: host, Port: port}
		return r.Identity(), nil
	case BackendWebDAV:
		u, err := normalizeURL(raw, true)
		return origin(u), err
	}
	return "", fmt.Errorf("backend must be one of %s", strings.Join(Backends, ", "))
}

// Validate normalises the endpoint and checks that the backend's credential comes
// from exactly one source. Files are read, so a missing one fails here.
func (p *Profile) Validate() error {
	p.Backend = strings.ToLower(strings.TrimSpace(p.Backend))
	if !slices.Contains(Backends, p.Backend) {
		return fmt.Errorf("backend must be one of %s", strings.Join(Backends, ", "))
	}
	endpoint, err := NormalizeEndpoint(p.Backend, p.Endpoint)
	if err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	p.Endpoint = endpoint
	p.SecretFile, p.KeyFile = strings.TrimSpace(p.SecretFile), strings.TrimSpace(p.KeyFile)
	if p.KeyFile != "" && p.Backend != BackendSFTP {
		return errors.New("a key file is for SFTP profiles only")
	}
	if p.EnvAuth && p.Backend != BackendS3 {
		return errors.New("environment authentication is for S3 profiles only")
	}

	s := p.Secrets
	set := func(vals ...string) (n int) {
		for _, v := range vals {
			if strings.TrimSpace(v) != "" {
				n++
			}
		}
		return n
	}
	if p.Backend == BackendS3 {
		s.AccessKeyID, s.SecretAccessKey = strings.TrimSpace(s.AccessKeyID), strings.TrimSpace(s.SecretAccessKey)
		p.Secrets = Secrets{AccessKeyID: s.AccessKeyID, SecretAccessKey: s.SecretAccessKey}
		switch {
		case p.EnvAuth && set(s.AccessKeyID, s.SecretAccessKey, p.SecretFile) > 0:
			return errors.New("an environment-authenticated profile takes no keys")
		case p.EnvAuth:
			return nil
		case s.AccessKeyID == "":
			return errors.New("set the access key id (or use the agent's environment)")
		case set(s.SecretAccessKey, p.SecretFile) != 1:
			return errors.New("set either the secret access key or a file holding it")
		}
	} else {
		var sources int
		switch p.Backend {
		case BackendAzure, BackendAzureFiles:
			sources = set(s.AccountKey, s.SASURL, p.SecretFile)
		case BackendSFTP:
			sources = set(s.Password, s.KeyPEM, p.SecretFile, p.KeyFile)
		case BackendSMB, BackendFTP:
			sources = set(s.Password, p.SecretFile)
		case BackendWebDAV:
			sources = set(s.Password, s.BearerToken, p.SecretFile)
		}
		if sources != 1 {
			return errors.New("set exactly one credential: a secret, or a file holding it")
		}
		if p.Secrets, err = cleanSecrets(p.Backend, p.Endpoint, s); err != nil {
			return err
		}
	}
	_, err = p.Credentials()
	return err
}

// Credentials returns the credential, reading the files when set
func (p *Profile) Credentials() (Secrets, error) {
	s := p.Secrets
	if p.SecretFile != "" {
		v, err := readSecretFile(p.SecretFile)
		if err != nil {
			return s, err
		}
		switch p.Backend {
		case BackendS3:
			s.SecretAccessKey = v
		case BackendAzure, BackendAzureFiles:
			s.AccountKey = v
		default:
			s.Password = v
		}
	}
	if p.KeyFile != "" {
		v, err := readSecretFile(p.KeyFile)
		if err != nil {
			return s, err
		}
		if _, err := ssh.ParseRawPrivateKey([]byte(v)); err != nil {
			return s, fmt.Errorf("the key file %s: %v (it must be unencrypted)", p.KeyFile, err)
		}
		s.KeyPEM = v
	}
	return s, nil
}

func readSecretFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	v := strings.TrimSpace(string(data))
	if v == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return v, nil
}

// Summary describes the profile without its credential
func (p *Profile) Summary(name string) ProfileSummary {
	return ProfileSummary{Name: name, Backend: p.Backend, Endpoint: p.Endpoint,
		Files: p.SecretFile != "" || p.KeyFile != "", EnvAuth: p.EnvAuth}
}

// Matches refuses a profile made for another backend or endpoint than the remote's
func (p *Profile) Matches(r *Remote) error {
	if p.Backend != r.Backend || p.Endpoint != r.Identity() {
		return fmt.Errorf("the profile is for %s %s, but the job's remote is %s %s", p.Backend, p.Endpoint, r.Backend, r.Identity())
	}
	return nil
}
