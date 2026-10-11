//go:build windows

package runtime

import "errors"

func execSelf(string) error { return errors.New("self-update is not supported on Windows") }
