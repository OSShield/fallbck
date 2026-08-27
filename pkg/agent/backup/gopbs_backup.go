package backup

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/pbs"
)

// runBackup mirrors gopbs.Backup but names the archive roots itself: a single directory
// is the archive root as in gopbs; several paths are placed under the virtual root under
// the names from ArchiveEntryNames (archive.AddDirectoryAs, gopbs >= 0.1.5).
func runBackup(ctx context.Context, opts gopbs.BackupOptions) (*gopbs.BackupResult, error) {
	if opts.Format != gopbs.FormatV1 && opts.Format != gopbs.FormatV2 {
		return nil, fmt.Errorf("unknown archive format %d", opts.Format)
	}
	if len(opts.Paths) == 0 {
		return nil, errors.New("nothing to back up")
	}
	if len(opts.Blobs) > 0 || len(opts.Streams) > 0 {
		return nil, errors.New("blobs and streams are not supported by the agent backup engine")
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
	arch, err := archive.New(archOpts)
	if err != nil {
		return nil, err
	}

	names := map[string]string{}
	if len(opts.Paths) > 1 {
		if names, err = ArchiveEntryNames(opts.Paths); err != nil {
			return nil, err
		}
	}
	for _, path := range opts.Paths {
		info, err := os.Lstat(path)
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

	metaName, payloadName := pbs.SplitIndexNames(arch.CatalogEntryName())
	if opts.Format == gopbs.FormatV2 {
		result.ArchiveName = metaName
	} else {
		result.ArchiveName = arch.CatalogEntryName()
	}

	clientCfg := opts.Client
	if opts.OnProgress != nil {
		totals := map[string]uint64{}
		if opts.Format == gopbs.FormatV2 {
			if m, p, err := arch.EstimatedSizeV2(); err == nil {
				totals[metaName], totals[payloadName] = uint64(m), uint64(p)
			}
		} else if t, err := arch.EstimatedSizeV1(); err == nil {
			totals[result.ArchiveName] = uint64(t)
		}
		userProgress := clientCfg.OnUploadProgress
		clientCfg.OnUploadProgress = func(name string, stats pbs.UploadStats, done bool) {
			if userProgress != nil {
				userProgress(name, stats, done)
			}
			opts.OnProgress(gopbs.Progress{Archive: name, Total: totals[name], Stats: stats, Done: done})
		}
	}

	client, err := pbs.NewClient(clientCfg)
	if err != nil {
		return nil, err
	}
	sess, err := client.StartBackup(ctx, opts.Ref)
	if err != nil {
		return nil, err
	}
	defer sess.Abort() // no-op after a successful Finish
	result.Ref = sess.Ref()

	switch opts.Format {
	case gopbs.FormatV2:
		meta, payload, err := arch.GenerateV2(ctx)
		if err != nil {
			return nil, err
		}
		result.Archive, result.Payload, err = sess.UploadPXARv2(ctx, result.ArchiveName, meta, payload)
		meta.Close()
		payload.Close()
		if err != nil {
			return nil, err
		}
	default:
		stream, err := arch.GenerateV1(ctx)
		if err != nil {
			return nil, err
		}
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
			result.Catalog, err = sess.UploadCatalog(ctx, catStream)
			catStream.Close()
			if err != nil {
				return nil, err
			}
		}
	}

	if err := sess.Finish(ctx); err != nil {
		return nil, err
	}
	return result, nil
}
