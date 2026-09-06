package dbbackup

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

// Passwordless local authentication: when a job carries no credentials at all (no
// password, no matching profile) and the agent runs as root on the database host,
// the run uses what the engine grants the local superuser without a password:
//
//   - PostgreSQL: peer authentication over the unix socket, running the client tools
//     as the OS user of the role (default postgres);
//   - MySQL / MariaDB: the unix socket as OS root, which the auth_socket / unix_socket
//     plugin maps to root@localhost (the Debian, Ubuntu and MariaDB default);
//   - MongoDB: an unauthenticated connection (no user), as when authorization is off;
//   - SQL Server: integrated authentication as the agent's service account (Windows
//     only; on Linux SQL Server has no passwordless local login).
//
// Nothing here is guessed from remote hosts: the job's host must be this machine.

// Well-known socket locations, checked in order
var (
	pgSocketDirs = []string{"/var/run/postgresql", "/run/postgresql", "/tmp"}
	// mysqlSocketPaths: Debian/Ubuntu, RHEL/Fedora, source and container images
	mysqlSocketPaths = []string{"/var/run/mysqld/mysqld.sock", "/run/mysqld/mysqld.sock", "/var/lib/mysql/mysql.sock", "/tmp/mysql.sock"}
)

// localCredentials builds the credentials for the passwordless fallback or explains
// why it does not apply. It never contacts the database.
func localCredentials(ctx context.Context, spec *dbspec.Spec) (dbspec.Credentials, error) {
	creds := dbspec.Credentials{Host: spec.EffectiveHost(), Port: spec.EffectivePort(), TLS: spec.TLS}
	if spec.Kubernetes != nil {
		return creds, fmt.Errorf("not available for kubernetes targets")
	}
	if !isLocalHost(ctx, spec.Host) {
		return creds, fmt.Errorf("host %q is not this machine", spec.Host)
	}
	switch spec.Engine {
	case dbspec.EngineMSSQL:
		return localMSSQLCredentials(spec, creds)
	case dbspec.EngineMongoDB:
		if spec.User != "" {
			return creds, fmt.Errorf("MongoDB user %q needs a password (only an unauthenticated connection works without one)", spec.User)
		}
		creds.User, creds.Source = "", "local:none"
		return creds, nil
	}
	if !isRoot() {
		return creds, fmt.Errorf("the agent is not running as root")
	}
	switch spec.Engine {
	case dbspec.EnginePostgres:
		role := spec.User
		if role == "" {
			role = "postgres"
		}
		if err := osUserExists(role); err != nil {
			return creds, fmt.Errorf("peer authentication maps OS users to roles of the same name, but %w", err)
		}
		dir := spec.Host
		if !spec.IsSocket() {
			var err error
			if dir, err = findPGSocketDir(creds.Port); err != nil {
				return creds, err
			}
		}
		creds.User, creds.Host, creds.RunAs, creds.Source = role, dir, role, "local:peer"
		creds.TLS = dbspec.TLSSpec{}
		return creds, nil
	case dbspec.EngineMySQL:
		if spec.User != "" && spec.User != "root" {
			return creds, fmt.Errorf("socket authentication as OS root only works for the root@localhost account, the job names user %q", spec.User)
		}
		sock := spec.Host
		if !spec.IsSocket() {
			var err error
			if sock, err = findMySQLSocket(); err != nil {
				return creds, err
			}
		}
		creds.User, creds.Host, creds.Source = "root", sock, "local:socket"
		creds.TLS = dbspec.TLSSpec{}
		return creds, nil
	}
	return creds, fmt.Errorf("not available for engine %s", spec.Engine)
}

// findPGSocketDir looks for the server's .s.PGSQL.<port> in the usual directories
func findPGSocketDir(port int) (string, error) {
	name := fmt.Sprintf(".s.PGSQL.%d", port)
	for _, dir := range pgSocketDirs {
		if isSocket(filepath.Join(dir, name)) {
			return dir, nil
		}
	}
	return "", fmt.Errorf("no PostgreSQL socket %s in %s (is the server running here? set the job's host to its socket directory otherwise)", name, strings.Join(pgSocketDirs, ", "))
}

// findMySQLSocket looks for the server socket in the usual places
func findMySQLSocket() (string, error) {
	for _, p := range mysqlSocketPaths {
		if isSocket(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("no MySQL/MariaDB socket in %s (is the server running here? set the job's host to its socket path otherwise)", strings.Join(mysqlSocketPaths, ", "))
}

func isSocket(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode()&os.ModeSocket != 0
}

// isLocalHost reports whether host names this machine: a socket path, a loopback
// name or address, the machine's own hostname, or a name resolving only to
// addresses of local interfaces. Unresolvable names are not local.
func isLocalHost(ctx context.Context, host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.HasPrefix(host, "/") {
		return true
	}
	// SQL Server: host\instance, "." for the default local instance
	if i := strings.IndexByte(host, '\\'); i >= 0 {
		host = host[:i]
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	switch host {
	case ".", "localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || isLocalIP(ip)
	}
	if hn, err := os.Hostname(); err == nil {
		hn = strings.ToLower(hn)
		if host == hn || host == strings.SplitN(hn, ".", 2)[0] || strings.SplitN(host, ".", 2)[0] == hn {
			return true
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		if !a.IP.IsLoopback() && !isLocalIP(a.IP) {
			return false
		}
	}
	return true
}

// isLocalIP reports whether ip is assigned to one of this machine's interfaces
func isLocalIP(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}
