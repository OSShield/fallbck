//go:build windows || plan9

package audit

import "errors"

func syslogExport(string) (Export, error) {
	return nil, errors.New("audit.export: syslog is not available on this platform")
}
