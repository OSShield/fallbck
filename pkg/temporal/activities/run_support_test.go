package activities

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/osshield/fallbck/pkg/agent/backup"
	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	"github.com/osshield/fallbck/pkg/m365"
	"github.com/osshield/fallbck/pkg/temporal"
	sdktemporal "go.temporal.io/sdk/temporal"
	"google.golang.org/grpc"
)

type nopConn struct{ grpc.ClientConnInterface }

func TestOpenTransport(t *testing.T) {
	ctx := context.Background()
	direct := &temporal.BackupSessionInfo{DirectPBS: true, Ticket: "t1"}
	tunnel := &temporal.BackupSessionInfo{Ticket: "t2"}

	if _, err := openTransport(ctx, direct, nil, nil, nil, nil); !errors.Is(err, errNoCredentialsFetcher) || !isTransportConfigErr(err) {
		t.Errorf("direct without fetcher: %v", err)
	}
	if _, err := openTransport(ctx, tunnel, nil, nil, nil, nil); !errors.Is(err, errNoTunnel) || !isTransportConfigErr(err) {
		t.Errorf("tunnel job without tunnel: %v", err)
	}
	boom := errors.New("pbs says no")
	pt := newPhaseTracker()
	_, err := openTransport(ctx, direct, nil, func(context.Context, string) (*backup.DirectOptions, error) { return nil, boom }, nil, pt)
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
	}, nil, nil)
	if err != nil || tr.direct != want || tr.dial != nil || gotTicket != "t1" {
		t.Errorf("direct transport: %v %+v ticket %q", err, tr, gotTicket)
	}
	tr, err = openTransport(ctx, tunnel, nopConn{}, nil, nil, nil)
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

func TestOpenTransportEncrypted(t *testing.T) {
	ctx := context.Background()
	creds := func(context.Context, string) (*backup.DirectOptions, error) { return &backup.DirectOptions{}, nil }
	enc := &temporal.BackupSessionInfo{DirectPBS: true, Ticket: "t1", Encrypted: true, KeyFingerprint: "ab:cd"}

	if _, err := openTransport(ctx, enc, nil, creds, nil, nil); !errors.Is(err, errNoKeyFetcher) || !isTransportConfigErr(err) {
		t.Errorf("encrypted without a key fetcher must be a config error: %v", err)
	}
	if _, err := openTransport(ctx, enc, nil, creds, func(context.Context, string) (*backup.Encryption, error) { return nil, nil }, nil); !errors.Is(err, errNoKey) {
		t.Errorf("encrypted but the server returned no key: %v", err)
	}
	boom := errors.New("server down")
	if _, err := openTransport(ctx, enc, nil, creds, func(context.Context, string) (*backup.Encryption, error) { return nil, boom }, nil); !errors.Is(err, boom) || isTransportConfigErr(err) {
		t.Errorf("fetch failure passes through: %v", err)
	}
	key, err := backup.NewEncryption("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", "ab:cd", time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	pt := newPhaseTracker()
	tr, err := openTransport(ctx, enc, nil, creds, func(_ context.Context, ticket string) (*backup.Encryption, error) {
		if ticket != "t1" {
			t.Errorf("ticket %q", ticket)
		}
		return key, nil
	}, pt)
	if err != nil || tr.crypt != key || tr.direct == nil {
		t.Fatalf("encrypted transport: %v %+v", err, tr)
	}
	if !strings.HasPrefix(pt.Current(), "fetching encryption key") {
		t.Errorf("phase %q", pt.Current())
	}
	o := tr.options(backup.Options{})
	if o.Crypt != key || o.Direct == nil {
		t.Errorf("options: %+v", o)
	}
	tr.close()
	if key.Config.Key != [32]byte{} {
		t.Error("close must wipe the key")
	}
	// A plaintext target gets no key even when a fetcher exists
	plain := &temporal.BackupSessionInfo{DirectPBS: true, Ticket: "t2"}
	if tr, err := openTransport(ctx, plain, nil, creds, func(context.Context, string) (*backup.Encryption, error) {
		t.Error("fetcher must not be called for a plaintext target")
		return nil, nil
	}, nil); err != nil || tr.crypt != nil {
		t.Errorf("plaintext: %v %+v", err, tr)
	}
}

// A job's Microsoft 365 profile replaces the server's ids-only credentials, but only
// when it was made for that tenant and app
func TestApplyM365Profile(t *testing.T) {
	const tenant, client = "72f988bf-86f1-41af-91ab-2d7cd011db47", "11111111-2222-3333-4444-555555555555"
	profile := &m365.Profile{TenantID: tenant, ClientID: client, AuthMethod: m365.AuthSecret, Secret: "agent-secret"}
	lookup := func(name string) (*m365.Profile, error) {
		if name != "contoso" {
			return nil, errors.New("profile not found")
		}
		return profile, nil
	}
	fromServer := func() *m365.Credentials {
		return &m365.Credentials{TenantID: tenant, ClientID: client, AuthMethod: m365.AuthAgent}
	}

	creds := fromServer()
	if err := applyM365Profile(creds, "", lookup); err != nil || creds.Secret != "" {
		t.Fatalf("no profile must leave the server's credentials: %+v %v", creds, err)
	}
	if err := applyM365Profile(creds, "contoso", lookup); err != nil || creds.Secret != "agent-secret" || creds.AuthMethod != m365.AuthSecret {
		t.Fatalf("profile not applied: %+v %v", creds, err)
	}

	creds = fromServer()
	creds.TenantID = "fabrikam.onmicrosoft.com"
	if err := applyM365Profile(creds, "contoso", lookup); !dbrun.IsPrecheck(err) || !strings.Contains(err.Error(), "fabrikam") || creds.Secret != "" {
		t.Errorf("profile used for another tenant: %v", err)
	}
	if err := applyM365Profile(fromServer(), "missing", lookup); !dbrun.IsPrecheck(err) || !strings.Contains(err.Error(), "m365 profile create") {
		t.Errorf("missing profile: %v", err)
	}
	if err := applyM365Profile(fromServer(), "contoso", nil); !dbrun.IsPrecheck(err) {
		t.Errorf("no store: %v", err)
	}
}
