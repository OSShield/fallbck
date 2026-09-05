package k8sbackup

import "errors"

// errorsAs is a tiny indirection so dump.go reads cleanly
func errorsAs(err error, target any) bool { return errors.As(err, target) }
