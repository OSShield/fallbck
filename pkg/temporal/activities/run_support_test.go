package activities

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/osshield/fallbck/pkg/agent/backup"
	"github.com/osshield/fallbck/pkg/temporal"
	sdktemporal "go.temporal.io/sdk/temporal"
	"google.golang.org/grpc"
)

type nopConn struct{ grpc.ClientConnInterface }

func TestOpenTransport(t *testing.T) {
	ctx := context.Background()
	direct := &temporal.BackupSessionInfo{DirectPBS: true, Ticket: "t1"}
	tunnel := &temporal.BackupSessionInfo{Ticket: "t2"}

	if _, err := openTransport(ctx, direct, nil, nil, nil); !errors.Is(err, errNoCredentialsFetcher) || !isTransportConfigErr(err) {
		t.Errorf("direct without fetcher: %v", err)
	}
	if _, err := openTransport(ctx, tunnel, nil, nil, nil); !errors.Is(err, errNoTunnel) || !isTransportConfigErr(err) {
		t.Errorf("tunnel job without tunnel: %v", err)
	}
	boom := errors.New("pbs says no")
	pt := newPhaseTracker()
	_, err := openTransport(ctx, direct, nil, func(context.Context, string) (*backup.DirectOptions, error) { return nil, boom }, pt)
	if !errors.Is(err, boom) || isTransportConfigErr(err) {
		t.Errorf("fetch failure must pass through and not count as a config error: %v", err)
	}
	if !strings.HasPrefix(pt.Current(), "fetching PBS credentials") {
		t.Errorf("phase %q", pt.Current())
	}
	var gotTicket string
	want := &backup.DirectOptions{}
	tr, err := openTransport(ctx, direct, nil, func(_ context.Context, ticket string) (*backup.DirectOptions, error) {
		gotTicket = ticket
		return want, nil
	}, nil)
	if err != nil || tr.direct != want || tr.dial != nil || gotTicket != "t1" {
		t.Errorf("direct transport: %v %+v ticket %q", err, tr, gotTicket)
	}
	tr, err = openTransport(ctx, tunnel, nopConn{}, nil, nil)
	if err != nil || tr.dial == nil || tr.direct != nil {
		t.Errorf("tunnel transport: %v %+v", err, tr)
	}
}

func TestPrecheckFailedIsNonRetryableWithDetails(t *testing.T) {
	pt := newPhaseTracker()
	pt.Set("checking the host")
	res, err := precheckFailed("Docker host backup", errors.New("not a docker host"), pt, func() string { return "tail" })
	if res == nil || res.ErrorMessage != "not a docker host" {
		t.Fatalf("result %+v", res)
	}
	var app *sdktemporal.ApplicationError
	if !errors.As(err, &app) || !app.NonRetryable() || app.Type() != ErrTypeDBPrecheckFailed {
		t.Fatalf("error %v", err)
	}
	var details temporal.BackupFailureDetails
	if err := app.Details(&details); err != nil || !strings.HasPrefix(details.Phase, "checking the host") || details.LogTail != "tail" {
		t.Errorf("details %+v (%v)", details, err)
	}
}
