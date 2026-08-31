package dbbackup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

type binlogFile struct {
	Name string
	Size int64
}

var binlogSeqRe = regexp.MustCompile(`\.(\d+)$`)

func binlogSeq(name string) int {
	if m := binlogSeqRe.FindStringSubmatch(name); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return -1
}

// selectBinlogRange picks the binary logs to fetch: from the previous run's file (or
// the oldest available when it was purged; the current file on a first run) up to
// and including the current file. gap reports a broken chain.
func selectBinlogRange(logs []binlogFile, prevFile, currentFile string) (files []binlogFile, gap bool) {
	sort.Slice(logs, func(i, j int) bool { return binlogSeq(logs[i].Name) < binlogSeq(logs[j].Name) })
	from := currentFile
	if prevFile != "" {
		found := false
		for _, l := range logs {
			if l.Name == prevFile {
				found = true
				break
			}
		}
		if found {
			from = prevFile
		} else if len(logs) > 0 {
			from, gap = logs[0].Name, true
		}
	}
	fromSeq, toSeq := binlogSeq(from), binlogSeq(currentFile)
	for _, l := range logs {
		if s := binlogSeq(l.Name); s >= fromSeq && s <= toSeq {
			files = append(files, l)
		}
	}
	return files, gap
}

// fetchBinlogs downloads the binary logs since the previous run with mysqlbinlog --raw
func fetchBinlogs(ctx context.Context, req *DumpRequest, connArgs []string, bl *dbspec.MySQLBinlog, restore *[]string) error {
	req.progress("binlog", "")
	q, err := mysqlConnect(ctx, req.Creds)
	if err != nil {
		return fmt.Errorf("connecting for binary log listing: %w", err)
	}
	rows, err := q.queryRows(ctx, "SHOW BINARY LOGS")
	q.close()
	if err != nil {
		return fmt.Errorf("listing binary logs (needs REPLICATION CLIENT / BINLOG MONITOR): %w", err)
	}
	var logs []binlogFile
	for _, r := range rows {
		if len(r) >= 2 {
			logs = append(logs, binlogFile{Name: r[0], Size: int64(atoi(r[1]))})
		}
	}

	var prevFile string
	if req.PrevState != nil && req.PrevState.LastSuccess != nil && req.PrevState.LastSuccess.MySQL != nil {
		prev := req.PrevState.LastSuccess.MySQL
		sameServer := prev.ServerID == bl.ServerID && (prev.ServerUUID == "" || bl.ServerUUID == "" || prev.ServerUUID == bl.ServerUUID)
		if sameServer {
			prevFile = prev.BinlogFile
			bl.Previous = &dbspec.BinlogPrevious{BinlogPosition: dbspec.BinlogPosition{File: prev.BinlogFile, Position: prev.BinlogPos}, RunID: req.PrevState.LastSuccess.RunID, Snapshot: req.PrevState.LastSuccess.Snapshot}
			bl.CoversFrom = &dbspec.BinlogPosition{File: prev.BinlogFile, Position: prev.BinlogPos}
		} else {
			bl.ChainReset = true
		}
	}
	files, gap := selectBinlogRange(logs, prevFile, bl.File)
	bl.ChainGap = gap
	if gap || bl.CoversFrom == nil {
		if len(files) > 0 {
			bl.CoversFrom = &dbspec.BinlogPosition{File: files[0].Name, Position: 4}
		}
	}
	bl.CoversTo = &dbspec.BinlogPosition{File: bl.File, Position: bl.Position}

	dir := filepath.Join(req.SpoolDir, "mysql", "binlog")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tool := req.Tools.Binaries["binlog"]
	for _, f := range files {
		req.progress("binlog", f.Name)
		args := append(append([]string{}, connArgs...), "--read-from-remote-server", "--raw", "--result-file="+dir+string(os.PathSeparator), f.Name)
		if _, err := req.Runner.Run(ctx, Command{Name: filepath.Base(tool.Path), Path: tool.Path, Args: args, Env: baseEnv()}); err != nil {
			return fmt.Errorf("fetching binary log %s (needs REPLICATION SLAVE): %w", f.Name, err)
		}
		local := filepath.Join(dir, f.Name)
		size := fileSize(local)
		if size < f.Size && f.Name != bl.File {
			return fmt.Errorf("binary log %s is incomplete: %d of %d bytes", f.Name, size, f.Size)
		}
		bl.Files = append(bl.Files, dbspec.FileEntry{Path: "mysql/binlog/" + f.Name, SizeBytes: size, Kind: "binlog"})
	}
	if len(files) > 0 {
		names := make([]string, len(files))
		for i, f := range files {
			names[i] = "mysql/binlog/" + f.Name
		}
		binlogClient, client := "mysqlbinlog", "mysql"
		if tool.Flavor == "mariadb" {
			binlogClient, client = "mariadb-binlog", "mariadb"
		}
		*restore = append(*restore,
			"# replay the binary logs captured since the previous snapshot (optional point-in-time):",
			fmt.Sprintf("%s --start-position=%d %s --stop-datetime='YYYY-MM-DD HH:MM:SS' | %s --defaults-extra-file=restore.cnf",
				binlogClient, bl.CoversFrom.Position, strings.Join(names, " "), client),
		)
	}
	return nil
}
