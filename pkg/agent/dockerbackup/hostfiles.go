package dockerbackup

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// helperLabel marks the throwaway containers this package creates
const helperLabel = "fallbck.io/helper"

// hostFiles reads files from the Docker host: directly when the path is visible in
// the agent's mount namespace, otherwise through a helper container that bind-mounts
// the directory read-only (the agent running as a container without that mount).
type hostFiles struct {
	client *Client
	// mode is the volume access setting; direct never uses helpers
	mode        string
	helperImage string
	runID       string
	seq         int
}

// read returns the file contents and how they were read (direct | helper)
func (h *hostFiles) read(ctx context.Context, p string) ([]byte, string, error) {
	if data, err := os.ReadFile(p); err == nil {
		return data, "direct", nil
	} else if h.mode == "direct" || h.client == nil {
		return nil, "direct", err
	} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
		return nil, "direct", err
	}
	data, err := h.readViaHelper(ctx, p)
	return data, "helper", err
}

// readViaHelper mounts the file's directory into a helper container and streams the
// single file out of it
func (h *hostFiles) readViaHelper(ctx context.Context, p string) ([]byte, error) {
	dir, base := filepath.Split(filepath.Clean(p))
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("host path %s must be absolute", p)
	}
	id, err := h.createHelper(ctx, []string{dir + ":/src:ro"})
	if err != nil {
		return nil, err
	}
	defer h.removeHelper(id)
	rc, err := h.client.Archive(ctx, id, path.Join("/src", base))
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("%s: not in the helper archive", p)
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeReg && path.Base(hdr.Name) == base {
			return io.ReadAll(io.LimitReader(tr, 64<<20))
		}
	}
}

func (h *hostFiles) createHelper(ctx context.Context, binds []string) (string, error) {
	if err := h.client.EnsureImage(ctx, h.helperImage); err != nil {
		return "", fmt.Errorf("helper image: %w", err)
	}
	h.seq++
	name := fmt.Sprintf("fallbck-helper-%s-%d", shortID(h.runID), h.seq)
	id, err := h.client.CreateHelper(ctx, HelperSpec{
		Name: name, Image: h.helperImage, Binds: binds,
		Labels: map[string]string{helperLabel: "true", "fallbck.io/run": h.runID},
	})
	if err != nil {
		return "", fmt.Errorf("creating helper container: %w", err)
	}
	return id, nil
}

// removeHelper deletes a helper with a fresh context so cancellation never leaks it
func (h *hostFiles) removeHelper(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	_ = h.client.RemoveContainer(ctx, id)
}

// shortID keeps the first 8 characters of a run id for container names
func shortID(s string) string {
	s = strings.ReplaceAll(s, "-", "")
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// SweepHelpers removes helper containers left behind by an interrupted run
func SweepHelpers(ctx context.Context, client *Client) int {
	list, err := client.ListContainers(ctx, true)
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range list {
		if c.Labels[helperLabel] != "true" {
			continue
		}
		if client.RemoveContainer(ctx, c.ID) == nil {
			n++
		}
	}
	return n
}
