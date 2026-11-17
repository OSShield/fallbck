// Package remote runs remote jobs on the agent: it reads S3, Azure Blob, SFTP, SMB
// and WebDAV storage through librc and archives it with gopbs.
package remote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	rclonefs "github.com/rclone/rclone/fs"
	libfs "github.com/scheiblingco/librc/fs"
	"github.com/scheiblingco/librc/remote/azure"
	"github.com/scheiblingco/librc/remote/s3"
	"github.com/scheiblingco/librc/remote/sftp"
	"github.com/scheiblingco/librc/remote/smb"
	"github.com/scheiblingco/librc/remote/webdav"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	spec "github.com/osshield/fallbck/pkg/remote"
)

// Source is the read-only view of one root that a run gets: librc's writes
// (Put, Remove, Purge and the rest) are never reachable from the run
type Source interface {
	// Walk lists everything below dir recursively; paths are relative to the root
	Walk(ctx context.Context, dir string, fn func(libfs.DirEntry) error) error
	Open(ctx context.Context, path string) (io.ReadCloser, error)
}

// Credentials is what the run authenticates with: the server's stored credential
// or the agent profile's (Profile.Credentials). EnvAuth (S3) uses the agent's
// environment or instance role instead.
type Credentials struct {
	spec.Secrets
	EnvAuth bool
}

// Session opens the roots of one remote for one run. Close it when the run ends:
// it removes the SFTP known_hosts file.
type Session struct {
	remote     *spec.Remote
	creds      Credentials
	knownHosts string
}

// NewSession checks the remote and prepares what the backend needs on disk. An SFTP
// remote without host keys is refused: rclone would accept any server key.
func NewSession(r *spec.Remote, creds Credentials) (*Session, error) {
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

// Open opens one root of the job: bucket[/prefix] (S3), container[/prefix] (Azure),
// share[/path] (SMB), or a path on the server (SFTP: absolute, "" is "/"; WebDAV:
// below the URL)
func (s *Session) Open(ctx context.Context, root string) (Source, error) {
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
		f, err = s3.New(ctx, s3.Config{Name: name, Bucket: root, Provider: s3.Provider(r.Provider), EnvAuth: c.EnvAuth,
			AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, Region: r.Region, Endpoint: r.Endpoint, ForcePathStyle: r.PathStyle})
	case spec.BackendAzure:
		f, err = azure.New(ctx, azure.Config{Name: name, Container: root, Account: r.Account, Key: c.AccountKey, SASUrl: c.SASURL, Endpoint: r.Endpoint})
	case spec.BackendSFTP:
		if s.knownHosts == "" {
			return nil, errors.New("sftp: the session is closed or has no host keys")
		}
		f, err = sftp.New(ctx, sftp.Config{Name: name, Host: r.Host, Port: r.EffPort(), User: r.User, Password: c.Password,
			KeyPEM: c.KeyPEM, KnownHostsFile: s.knownHosts, Root: "/" + root})
	case spec.BackendSMB:
		f, err = smb.New(ctx, smb.Config{Name: name, Host: r.Host, Port: r.EffPort(), User: r.User, Password: c.Password, Domain: r.Domain, Share: root})
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

// readOnly narrows a librc filesystem to Source
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
