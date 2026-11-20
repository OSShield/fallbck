// Package backends opens remotes through librc (and so rclone). Only the agent
// binary imports it: the run code in pkg/agent/remote gets it as a function, which
// keeps rclone out of the server, whose activities package links the agent's run
// code.
package backends

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"

	rclonefs "github.com/rclone/rclone/fs"
	libfs "github.com/scheiblingco/librc/fs"
	"github.com/scheiblingco/librc/remote/azure"
	"github.com/scheiblingco/librc/remote/azurefiles"
	"github.com/scheiblingco/librc/remote/ftp"
	"github.com/scheiblingco/librc/remote/s3"
	"github.com/scheiblingco/librc/remote/sftp"
	"github.com/scheiblingco/librc/remote/smb"
	"github.com/scheiblingco/librc/remote/webdav"

	"github.com/osshield/fallbck/pkg/agent/remote"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	spec "github.com/osshield/fallbck/pkg/remote"
)

// Session opens the roots of one remote for one run. Close it when the run ends:
// it removes the SFTP known_hosts file.
type Session struct {
	remote     *spec.Remote
	creds      remote.Credentials
	knownHosts string
}

// NewSession checks the remote and prepares what the backend needs on disk. An SFTP
// remote without host keys is refused: rclone would accept any server key.
func NewSession(r *spec.Remote, creds remote.Credentials) (remote.Opener, error) {
	return newSession(r, creds)
}

func newSession(r *spec.Remote, creds remote.Credentials) (*Session, error) {
	s := &Session{remote: r, creds: creds}
	if r.Backend == spec.BackendSFTP {
		path, err := writeKnownHosts(r)
		if err != nil {
			return nil, err
		}
		s.knownHosts = path
	}
	return s, nil
}

// Open opens one root of the job: bucket[/prefix] (S3), container[/prefix] (Azure
// Blob), share[/path] (SMB, Azure Files), or a path on the server (SFTP and FTP:
// absolute, "" is "/"; WebDAV: below the URL)
func (s *Session) Open(ctx context.Context, root string) (remote.Source, error) {
	r, c := s.remote, s.creds
	name := "fallbck-" + r.Backend
	var (
		f   libfs.Filesystem
		err error
	)
	switch r.Backend {
	case spec.BackendS3:
		// The listing's LastModified as the mtime: rclone otherwise HEADs every
		// object for its mtime metadata (and uses the current time when that fails,
		// which would defeat reuse). The backend keeps the config of this context.
		// ponytail: set through rclone directly, belongs in librc's s3.Config
		ctx, ci := rclonefs.AddConfig(ctx)
		ci.UseServerModTime = true
		f, err = s3.New(ctx, s.s3Config(root))
	case spec.BackendAzure:
		f, err = azure.New(ctx, s.azureConfig(root))
	case spec.BackendSFTP:
		if s.knownHosts == "" {
			return nil, errors.New("sftp: the session is closed or has no host keys")
		}
		f, err = sftp.New(ctx, sftp.Config{Name: name, Host: r.Host, Port: r.EffPort(), User: r.User, Password: c.Password,
			KeyPEM: c.KeyPEM, KnownHostsFile: s.knownHosts, Root: "/" + root})
	case spec.BackendAzureFiles:
		share, path, _ := strings.Cut(root, "/")
		f, err = azurefiles.New(ctx, azurefiles.Config{Name: name, ShareName: share, Root: path, Account: r.Account,
			Key: c.AccountKey, SASUrl: c.SASURL, Endpoint: r.Endpoint})
	case spec.BackendSMB:
		f, err = smb.New(ctx, s.smbConfig(root))
	case spec.BackendFTP:
		// the certificate is checked against the system CAs; there's no way to skip it
		f, err = ftp.New(ctx, ftp.Config{Name: name, Host: r.Host, Port: r.EffPort(), User: r.User, Password: c.Password,
			TLS: r.TLS == spec.FTPTLSImplicit, ExplicitTLS: r.TLS == spec.FTPTLSExplicit, Root: "/" + root})
	case spec.BackendWebDAV:
		f, err = webdav.New(ctx, webdav.Config{Name: name, URL: r.URL, Vendor: webdav.Vendor(r.Vendor), User: r.User,
			Password: c.Password, BearerToken: c.BearerToken, Root: root})
	default:
		return nil, fmt.Errorf("unknown backend %q", r.Backend)
	}
	if err != nil {
		return nil, err
	}
	return readOnly{f}, nil
}

// Discover lists the buckets (S3), containers (Azure Blob) or shares (SMB, without
// the administrative ones ending in $) the credential can see, sorted
func (s *Session) Discover(ctx context.Context) ([]string, error) {
	var (
		names []string
		err   error
	)
	switch s.remote.Backend {
	case spec.BackendS3:
		names, err = s3.ListBuckets(ctx, s.s3Config(""))
	case spec.BackendAzure:
		names, err = azure.ListContainers(ctx, s.azureConfig(""))
	case spec.BackendSMB:
		names, err = smb.ListShares(ctx, s.smbConfig(""))
	default:
		return nil, fmt.Errorf("%s remotes have no buckets to list", s.remote.Backend)
	}
	if err != nil {
		return nil, err
	}
	out := names[:0]
	for _, n := range names {
		if n != "" && !strings.HasSuffix(n, "$") {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (s *Session) s3Config(bucket string) s3.Config {
	r, c := s.remote, s.creds
	return s3.Config{Name: "fallbck-" + r.Backend, Bucket: bucket, Provider: s3.Provider(r.Provider), EnvAuth: c.EnvAuth,
		AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, Region: r.Region, Endpoint: r.Endpoint, ForcePathStyle: r.PathStyle}
}

func (s *Session) azureConfig(container string) azure.Config {
	r, c := s.remote, s.creds
	return azure.Config{Name: "fallbck-" + r.Backend, Container: container, Account: r.Account, Key: c.AccountKey, SASUrl: c.SASURL, Endpoint: r.Endpoint}
}

func (s *Session) smbConfig(share string) smb.Config {
	r, c := s.remote, s.creds
	return smb.Config{Name: "fallbck-" + r.Backend, Host: r.Host, Port: r.EffPort(), User: r.User, Password: c.Password, Domain: r.Domain, Share: share}
}

// Close removes the run's temporary files
func (s *Session) Close() error {
	if s.knownHosts == "" {
		return nil
	}
	err := os.Remove(s.knownHosts)
	s.knownHosts = ""
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// readOnly narrows a librc filesystem to remote.Source
type readOnly struct{ f libfs.Filesystem }

func (r readOnly) Walk(ctx context.Context, dir string, fn func(libfs.DirEntry) error) error {
	return r.f.Walk(ctx, dir, fn)
}

func (r readOnly) Open(ctx context.Context, path string) (io.ReadCloser, error) {
	return r.f.Open(ctx, path)
}

// writeKnownHosts writes the remote's host keys as a known_hosts file for its
// host and port (mode 0600)
func writeKnownHosts(r *spec.Remote) (string, error) {
	if len(r.KnownHosts) == 0 {
		return "", errors.New("sftp: the remote has no host keys; add the server's keys to the remote")
	}
	addr := knownhosts.Normalize(net.JoinHostPort(r.Host, strconv.Itoa(r.EffPort())))
	var b strings.Builder
	for _, line := range r.KnownHosts {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return "", fmt.Errorf("sftp: host key %q: %w", line, err)
		}
		b.WriteString(knownhosts.Line([]string{addr}, key) + "\n")
	}
	f, err := os.CreateTemp("", "fallbck-known-hosts-*")
	if err != nil {
		return "", err
	}
	_, werr := f.WriteString(b.String())
	if err := errors.Join(werr, f.Close()); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
