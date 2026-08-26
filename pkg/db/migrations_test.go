package db

import (
	"strings"
	"testing"
)

func TestLoadMigrations(t *testing.T) {
	migrations, err := LoadMigrations()
	if err != nil {
		t.Fatalf("LoadMigrations: %v", err)
	}
	if len(migrations) < 2 {
		t.Fatalf("expected at least 2 migrations, got %d", len(migrations))
	}
	for i, m := range migrations {
		if m.Version != i+1 {
			t.Errorf("migration %d has version %d; versions must be contiguous from 1", i, m.Version)
		}
		if !strings.HasSuffix(m.Name, ".sql") || strings.TrimSpace(m.SQL) == "" {
			t.Errorf("migration %q is empty or misnamed", m.Name)
		}
	}
	if migrations[0].Name != "001_initial_schema.sql" {
		t.Errorf("first migration = %q", migrations[0].Name)
	}
	if !strings.Contains(migrations[1].SQL, "api_keys") {
		t.Errorf("002 should create api_keys")
	}
}
