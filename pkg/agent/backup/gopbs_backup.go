package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/pbs"
)

// runBackup mirrors gopbs.Backup but names the archive roots itself: a single directory
// is the archive root as in gopbs; several paths are placed under the virtual root under
// the names from ArchiveEntryNames (archive.AddDirectoryAs, gopbs >= 0.1.5). With a
// cacheDir and format v2 it keeps a copy of the metadata stream and, when the copy
// matches the server's previous snapshot, skips reading unchanged files.
func runBackup(ctx context.Context, opts gopbs.BackupOptions, names map[string]string, cacheDir string, phase func(string)) (*gopbs.BackupResult, error) {
	if phase == nil {
		phase = func(string) {}
	}
	if opts.Format != gopbs.FormatV1 && opts.Format != gopbs.FormatV2 {
		return nil, fmt.Errorf("unknown archive format %d", opts.Format)
	}
	if len(opts.Paths) == 0 {
		return nil, errors.New("nothing to back up")
	}
	if len(opts.Streams) > 0 {
		return nil, errors.New("streams are not supported by the agent backup engine")
	}
	blobNames, err := blobFileNames(opts.Blobs)
	if err != nil {
		return nil, err
	}

	result := &gopbs.BackupResult{}

	archOpts := opts.Archive
	userWarn := archOpts.OnWarn
	archOpts.OnWarn = func(w archive.Warning) {
		result.Warnings = append(result.Warnings, w)
		if userWarn != nil {
			userWarn(w)
		}
	}
	// Index names derive from the archive name alone (no scanning involved)
	probe, err := archive.New(archOpts)
	if err != nil {
		return nil, err
	}
	metaName, payloadName := pbs.SplitIndexNames(probe.CatalogEntryName())
	if opts.Format == gopbs.FormatV2 {
		result.ArchiveName = metaName
	} else {
		result.ArchiveName = probe.CatalogEntryName()
	}

	clientCfg := opts.Client

	client, err := pbs.NewClient(clientCfg)
	if err != nil {
		return nil, err
	}
	phase("opening PBS session")
	sess, err := client.StartBackup(ctx, opts.Ref)
	if err != nil {
		return nil, err
	}
	defer sess.Abort() // no-op after a successful Finish
	result.Ref = sess.Ref()

	var cache *reuseCache
	if cacheDir != "" && opts.Format == gopbs.FormatV2 {
		cache = newReuseCache(cacheDir, metaName)
		phase("checking the previous snapshot")
		archOpts.Previous = cache.previous(ctx, sess, metaName, payloadName)
	}

	arch, err := archive.New(archOpts)
	if err != nil {
		return nil, err
	}

	if names == nil {
		names = map[string]string{}
		if len(opts.Paths) > 1 {
			if names, err = ArchiveEntryNames(opts.Paths); err != nil {
				return nil, err
			}
		}
	}
	for _, path := range opts.Paths {
		// Follow a symlinked root: a Windows job reads its paths through links to
		// Volume Shadow Copies, and a linked directory root means "back up the tree"
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		switch {
		case info.IsDir() && names[path] != "":
			err = arch.AddDirectoryAs(path, names[path])
		case info.IsDir():
			err = arch.AddDirectory(path)
		default:
			// Files keep their basename (gopbs has no AddFileAs); ArchiveEntryNames already
			// guarantees the basename is unique among the roots when it equals names[path].
			err = arch.AddFile(path)
		}
		if err != nil {
			return nil, err
		}
	}

	var cacheTmp *os.File
	switch opts.Format {
	case gopbs.FormatV2:
		meta, payload, err := arch.GenerateV2(ctx)
		if err != nil {
			return nil, err
		}
		var metaIn io.Reader = meta
		if cache != nil {
			if f, err := cache.begin(); err != nil {
				slog.Warn("Change detection: cannot write the metadata cache; the next run reads every file", "dir", cache.dir, "error", err)
			} else {
				cacheTmp = f
				metaIn = io.TeeReader(meta, f)
			}
		}
		phase("uploading " + result.ArchiveName)
		result.Archive, result.Payload, err = sess.UploadPXARv2(ctx, result.ArchiveName, metaIn, payload)
		meta.Close()
		payload.Close()
		if err != nil {
			cache.discard(cacheTmp)
			return nil, err
		}
		result.Reuse = arch.ReuseStats()
	default:
		stream, err := arch.GenerateV1(ctx)
		if err != nil {
			return nil, err
		}
		phase("uploading " + result.ArchiveName)
		result.Archive, err = sess.UploadPXARv1(ctx, result.ArchiveName, stream)
		stream.Close()
		if err != nil {
			return nil, err
		}
		if !opts.SkipCatalog {
			catStream, err := arch.GenerateCatalog(ctx)
			if err != nil {
				return nil, err
			}
			phase("uploading catalog")
			result.Catalog, err = sess.UploadCatalog(ctx, catStream)
			catStream.Close()
			if err != nil {
				return nil, err
			}
		}
	}

	if len(opts.Blobs) > 0 {
		enc := pbs.NewBlobEncoder()
		for i, b := range opts.Blobs {
			if err := sess.UploadBlob(ctx, enc, blobNames[i], b.Data, true); err != nil {
				return nil, err
			}
		}
	}

	phase("finalizing snapshot")
	if err := sess.Finish(ctx); err != nil {
		cache.discard(cacheTmp)
		return nil, err
	}
	if cacheTmp != nil {
		if err := cache.commit(cacheTmp, result.ArchiveName, snapshotString(result.Ref), result.Archive.Entries); err != nil {
			slog.Warn("Change detection: the metadata cache could not be saved; the next run reads every file", "dir", cache.dir, "error", err)
			cache.discard(cacheTmp)
		}
	}
	return result, nil
}

// blobFileNames mirrors gopbs: "<name>.blob", no path separators, index.json reserved
func blobFileNames(blobs []gopbs.Blob) ([]string, error) {
	names := make([]string, 0, len(blobs))
	seen := map[string]bool{}
	for _, b := range blobs {
		name := b.Name
		if name == "" || strings.ContainsAny(name, "/\\") {
			return nil, fmt.Errorf("invalid blob name %q", b.Name)
		}
		if !strings.HasSuffix(name, ".blob") {
			name += ".blob"
		}
		if name == "index.json.blob" {
			return nil, errors.New("blob name index.json is reserved for the snapshot manifest")
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate blob name %q", name)
		}
		seen[name] = true
		names = append(names, name)
	}
	return names, nil
}
