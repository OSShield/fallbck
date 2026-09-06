//go:build windows

package dbbackup

import (
	"fmt"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

var isRoot = func() bool { return false }

var osUserExists = func(name string) error {
	return fmt.Errorf("peer and socket authentication are not available on Windows")
}

// localMSSQLCredentials: integrated authentication as the agent's service account
func localMSSQLCredentials(spec *dbspec.Spec, creds dbspec.Credentials) (dbspec.Credentials, error) {
	if spec.User != "" {
		return creds, fmt.Errorf("SQL login %q needs a password; leave the user blank for integrated authentication", spec.User)
	}
	creds.User, creds.Source = "", "local:integrated"
	return creds, nil
}

func prepareDirFor(dir, name string) error {
	return fmt.Errorf("running client tools as another user is not supported on Windows")
}
