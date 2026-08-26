//go:build !sqlite

package embedded

import (
	"errors"

	"go.temporal.io/server/common/config"
)

// setupSQLite is only available when built with `-tags sqlite` (used by integration tests)
func setupSQLite(Config) (*config.SQL, error) {
	return nil, errors.New("sqlite persistence for the embedded temporal server requires building with -tags sqlite")
}
