package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/api"
	"github.com/osshield/fallbck/pkg/config"
)

func TestVCSStateSweeperThrottles(t *testing.T) {
	root := t.TempDir()
	orphan := uuid.New()
	if err := os.Mkdir(filepath.Join(root, orphan.String()), 0o700); err != nil {
		t.Fatal(err)
	}
	sweep := VCSStateSweeper(root, 0)
	sweep(nil) // marks
	sweep(nil) // within the interval: skipped, so the zero grace cannot delete yet
	if _, err := os.Stat(filepath.Join(root, orphan.String())); err != nil {
		t.Fatalf("the second sweep should have been skipped: %v", err)
	}
}

// TestHeartbeatDeliversVCSJobs: the list in the heartbeat answer reaches the hook;
// an answer without it (an older server) does not call the hook at all
func TestHeartbeatDeliversVCSJobs(t *testing.T) {
	job := uuid.New()
	for _, withList := range []bool{true, false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := api.HeartbeatResponse{Status: "ok"}
			if withList {
				resp.VCSJobs = &[]uuid.UUID{job}
			}
			_ = json.NewEncoder(w).Encode(resp)
		}))
		cfg := &config.AgentConfig{AgentID: uuid.NewString(), ServerURL: srv.URL}
		got := make(chan []uuid.UUID, 1)
		var calls atomic.Int64
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		done := make(chan struct{})
		go func() {
			StartHeartbeat(ctx, cfg, NewTokenStore(cfg, ""), Agent{VCSJobs: func(ids []uuid.UUID) {
				calls.Add(1)
				got <- ids
			}})
			close(done)
		}()
		if withList {
			select {
			case ids := <-got:
				if len(ids) != 1 || ids[0] != job {
					t.Errorf("jobs %v", ids)
				}
			case <-ctx.Done():
				t.Fatal("the hook was not called")
			}
		} else {
			time.Sleep(500 * time.Millisecond)
			if calls.Load() != 0 {
				t.Error("an answer without vcs_jobs must not call the hook")
			}
		}
		cancel()
		<-done
		srv.Close()
	}
}
