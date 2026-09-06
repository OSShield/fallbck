package dbbackup

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// psqlQuerier answers the precheck queries through psql instead of an in-process
// connection: peer authentication identifies the OS user on the socket, so a root
// agent must run the client as postgres to be postgres.
type psqlQuerier struct {
	path   string
	env    []string
	runAs  string
	runner Runner
}

const (
	psqlFieldSep = "\x1f" // unit separator between columns
	// records end with a NUL (--record-separator-zero)
)

func (q psqlQuerier) run(ctx context.Context, sql string) ([][]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var out bytes.Buffer
	args := []string{"--no-psqlrc", "--no-password", "--tuples-only", "--no-align",
		"--field-separator=" + psqlFieldSep, "--record-separator-zero", "--dbname=postgres", "--command=" + sql}
	if _, err := q.runner.Run(ctx, Command{Name: "psql", Path: q.path, Args: args, Env: q.env, Stdout: &out, RunAs: q.runAs}); err != nil {
		return nil, err
	}
	var rows [][]string
	for _, rec := range bytes.Split(out.Bytes(), []byte{0}) {
		s := strings.TrimSuffix(string(rec), "\n")
		if s == "" {
			continue
		}
		rows = append(rows, strings.Split(s, psqlFieldSep))
	}
	return rows, nil
}

func (q psqlQuerier) queryRow(ctx context.Context, sql string, dest ...any) error {
	rows, err := q.run(ctx, sql)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return fmt.Errorf("psql: query returned no rows")
	}
	if len(rows[0]) < len(dest) {
		return fmt.Errorf("psql: query returned %d columns, %d expected", len(rows[0]), len(dest))
	}
	for i, d := range dest {
		if err := scanString(d, rows[0][i]); err != nil {
			return fmt.Errorf("psql: column %d: %w", i+1, err)
		}
	}
	return nil
}

func (q psqlQuerier) queryRows(ctx context.Context, sql string) ([][]string, error) {
	return q.run(ctx, sql)
}

func (q psqlQuerier) close() {}

// scanString converts psql's text output into the destinations the engines scan into
func scanString(dest any, val string) error {
	switch d := dest.(type) {
	case *string:
		*d = val
	case *int:
		n, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil {
			return err
		}
		*d = n
	case *int64:
		n, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
		if err != nil {
			return err
		}
		*d = n
	case *bool:
		switch strings.TrimSpace(val) {
		case "t", "true", "1", "on":
			*d = true
		case "f", "false", "0", "off", "":
			*d = false
		default:
			return fmt.Errorf("not a boolean: %q", val)
		}
	default:
		return fmt.Errorf("unsupported scan destination %T", dest)
	}
	return nil
}
