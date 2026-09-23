package runtime

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/osshield/fallbck/pkg/agent/credstore"
	"github.com/osshield/fallbck/pkg/config"
	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

// MergeStoredProfiles overlays the encrypted credential store onto the profiles the
// configuration already carries (agent.yaml and FALLBCK_AGENT_DB_PROFILE_* env, both
// plain text). The store wins on a name clash. Plain-text profiles keep working but
// are logged once so operators know to import them.
func MergeStoredProfiles(cfg *config.AgentConfig) error {
	plain := make([]string, 0, len(cfg.DBBackup.Profiles))
	for name := range cfg.DBBackup.Profiles {
		plain = append(plain, name)
	}
	sort.Strings(plain)
	store := credstore.Open(cfg.DataDir)
	stored, err := store.Load()
	if err != nil {
		return fmt.Errorf("credential store: %w", err)
	}
	if cfg.DBBackup.Profiles == nil {
		cfg.DBBackup.Profiles = map[string]dbspec.CredentialProfile{}
	}
	for name, p := range stored {
		cfg.DBBackup.Profiles[name] = p
	}
	if len(plain) > 0 {
		slog.Warn("Credential profiles in plain text (agent.yaml or environment); move them into the encrypted store with: fallbck-agent database profile import",
			"profiles", strings.Join(plain, ", "), "store", store.Path())
	}
	return nil
}

// ProfileSummaries lists the profiles an agent will report to the server: names,
// engines, users and hosts, never passwords
func ProfileSummaries(cfg *config.AgentConfig) []dbspec.ProfileSummary {
	if cfg == nil {
		return nil
	}
	return credstore.Summaries(cfg.DBBackup.Profiles)
}
