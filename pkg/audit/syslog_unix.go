//go:build !windows && !plan9

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/syslog"
	"strings"

	"github.com/osshield/fallbck/pkg/db"
)

// syslogExport sends one message per entry (the entry as JSON) with the authpriv
// facility; "syslog:" is the local daemon, udp:// and tcp:// a remote one
func syslogExport(target string) (Export, error) {
	network, addr := "", ""
	if scheme, rest, ok := strings.Cut(target, "://"); ok && (scheme == "udp" || scheme == "tcp") {
		network, addr = scheme, rest
	}
	dial := func() (*syslog.Writer, error) {
		return syslog.Dial(network, addr, syslog.LOG_INFO|syslog.LOG_AUTHPRIV, "fallbck-audit")
	}
	w, err := dial()
	if err != nil {
		return nil, fmt.Errorf("audit.export %q: %w", target, err)
	}
	_ = w.Close()
	return func(_ context.Context, entries []*db.AuditEntry) error {
		w, err := dial()
		if err != nil {
			return err
		}
		defer w.Close()
		for _, e := range entries {
			b, err := json.Marshal(e)
			if err != nil {
				return err
			}
			if err := w.Info(string(b)); err != nil {
				return err
			}
		}
		return nil
	}, nil
}
