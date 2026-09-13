//go:build !windows

package vss

import "context"

const supported = false

func take(_ context.Context, _ string, paths []string) ([]string, *Snapshots, error) {
	return append([]string(nil), paths...), &Snapshots{}, nil
}

func release(*Snapshots) {}

func sweep(string) {}
