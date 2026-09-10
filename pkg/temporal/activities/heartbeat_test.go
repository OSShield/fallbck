package activities

import (
	"context"
	"errors"
	"testing"

	"github.com/osshield/fallbck/pkg/temporal"
	sdktemporal "go.temporal.io/sdk/temporal"
)

func TestBackupFailureClassifiesSnapshotConflict(t *testing.T) {
	pt := newPhaseTracker()
	pt.Set("upload")
	logTail := func() string { return "tail" }

	conflict := errors.New("pbs: dialing session: backup tunnel rejected: rpc error: code = InvalidArgument desc = PBS refused the backup session: 400 Bad Request: backup timestamp is older than last backup.")
	err := backupFailure(context.Background(), conflict, pt, logTail)
	var appErr *sdktemporal.ApplicationError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected an ApplicationError, got %T: %v", err, err)
	}
	if !appErr.NonRetryable() {
		t.Fatal("a snapshot conflict must not be retried with the same timestamp")
	}
	if appErr.Type() != ErrTypeBackupFailed {
		t.Fatalf("error type changed: %q", appErr.Type())
	}
	var details temporal.BackupFailureDetails
	if err := appErr.Details(&details); err != nil || details.LogTail != "tail" {
		t.Fatalf("details lost: %+v (%v)", details, err)
	}

	other := errors.New("connection reset")
	err = backupFailure(context.Background(), other, pt, logTail)
	if !errors.As(err, &appErr) || appErr.NonRetryable() {
		t.Fatalf("ordinary failures must stay retryable: %v", err)
	}
}
