package dbbackup

import (
	"encoding/json"
	"time"
)

// ManifestSchemaVersion is bumped on incompatible manifest changes
const ManifestSchemaVersion = 1

// ManifestFileName is the manifest inside the archive; the blob is ManifestBlobName + ".blob"
const (
	ManifestFileName = "fallbck-db.json"
	ManifestBlobName = "fallbck-db.json"
	// ArchiveName is the pxar archive holding the spool directory
	ArchiveName = "db"
)

// Manifest describes one database backup run; it is written into the archive root and
// uploaded as a separate blob so restores can start from it.
type Manifest struct {
	SchemaVersion int               `json:"schema_version"`
	Generator     ManifestGenerator `json:"generator"`
	Job           ManifestJob       `json:"job"`
	Snapshot      ManifestSnapshot  `json:"snapshot"`
	Engine        string            `json:"engine"`
	StartedAt     time.Time         `json:"started_at"`
	FinishedAt    time.Time         `json:"finished_at"`
	// ConsistentAsOf is the point in time the backup represents
	ConsistentAsOf time.Time         `json:"consistent_as_of"`
	Server         ManifestServer    `json:"server"`
	Tools          map[string]Tool   `json:"tools"`
	Spec           *Spec             `json:"spec"`
	Databases      []DatabaseEntry   `json:"databases"`
	Files          []FileEntry       `json:"files"`
	Warnings       []string          `json:"warnings,omitempty"`
	Notes          []string          `json:"notes,omitempty"`
	Postgres       *PostgresManifest `json:"postgres,omitempty"`
	MySQL          *MySQLManifest    `json:"mysql,omitempty"`
	MongoDB        *MongoManifest    `json:"mongodb,omitempty"`
	MSSQL          *MSSQLManifest    `json:"mssql,omitempty"`
	Restore        Restore           `json:"restore"`
}

type ManifestGenerator struct {
	Agent    string `json:"agent"`
	Version  string `json:"version"`
	Hostname string `json:"hostname"`
}

type ManifestJob struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	RunID       string `json:"run_id,omitempty"`
	BackupRunID string `json:"backup_run_id"`
}

type ManifestSnapshot struct {
	Type    string    `json:"type"`
	ID      string    `json:"id"`
	Time    time.Time `json:"time"`
	Archive string    `json:"archive"`
}

type ManifestServer struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user,omitempty"`
	Version    string `json:"version,omitempty"`
	VersionNum int    `json:"version_num,omitempty"`
	Flavor     string `json:"flavor,omitempty"`
	IsReplica  bool   `json:"is_replica,omitempty"`
}

// Tool is a detected client binary
type Tool struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

type DatabaseEntry struct {
	Name       string `json:"name"`
	File       string `json:"file,omitempty"`
	Format     string `json:"format,omitempty"`
	SizeBytes  int64  `json:"size_bytes"`
	SHA256     string `json:"sha256,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

type FileEntry struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256,omitempty"`
	Kind      string `json:"kind,omitempty"`
}

type PostgresManifest struct {
	Mode       string              `json:"mode"`
	Globals    *PostgresGlobals    `json:"globals,omitempty"`
	Basebackup *PostgresBasebackup `json:"basebackup,omitempty"`
	// WAL position of the server when the logical dumps were taken
	WALLSN string `json:"wal_lsn,omitempty"`
}

type PostgresGlobals struct {
	File                  string `json:"file"`
	RolePasswordsIncluded bool   `json:"role_passwords_included"`
}

type PostgresBasebackup struct {
	Dir          string   `json:"dir"`
	Files        []string `json:"files"`
	Label        string   `json:"label"`
	Timeline     int64    `json:"timeline,omitempty"`
	WALStartLSN  string   `json:"wal_start_lsn,omitempty"`
	WALEndLSN    string   `json:"wal_end_lsn,omitempty"`
	WALStartFile string   `json:"wal_start_file,omitempty"`
	WALEndFile   string   `json:"wal_end_file,omitempty"`
	WALSource    string   `json:"wal_source,omitempty"`
	Compression  string   `json:"compression"`
}

type MySQLManifest struct {
	Flavor                 string       `json:"flavor"`
	DumpFiles              []string     `json:"dump_files"`
	AllDatabases           bool         `json:"all_databases"`
	PerDatabase            bool         `json:"per_database"`
	SingleTransaction      bool         `json:"single_transaction"`
	FlushLogs              bool         `json:"flush_logs"`
	NonTransactionalTables int          `json:"non_transactional_tables"`
	Binlog                 *MySQLBinlog `json:"binlog,omitempty"`
}

type BinlogPosition struct {
	File     string `json:"file"`
	Position int64  `json:"position"`
}

type MySQLBinlog struct {
	Enabled        bool            `json:"enabled"`
	PositionSource string          `json:"position_source,omitempty"`
	File           string          `json:"file,omitempty"`
	Position       int64           `json:"position,omitempty"`
	GTID           string          `json:"gtid,omitempty"`
	GTIDMode       string          `json:"gtid_mode,omitempty"`
	ServerID       int64           `json:"server_id,omitempty"`
	ServerUUID     string          `json:"server_uuid,omitempty"`
	Previous       *BinlogPrevious `json:"previous,omitempty"`
	Files          []FileEntry     `json:"files,omitempty"`
	CoversFrom     *BinlogPosition `json:"covers_from,omitempty"`
	CoversTo       *BinlogPosition `json:"covers_to,omitempty"`
	ChainReset     bool            `json:"chain_reset"`
	ChainGap       bool            `json:"chain_gap"`
}

type BinlogPrevious struct {
	BinlogPosition
	RunID    string `json:"run_id,omitempty"`
	Snapshot string `json:"snapshot,omitempty"`
}

type MongoManifest struct {
	Dir            string   `json:"dir"`
	Oplog          bool     `json:"oplog"`
	OplogFile      string   `json:"oplog_file,omitempty"`
	Gzip           bool     `json:"gzip"`
	ReadPreference string   `json:"read_preference,omitempty"`
	Databases      []string `json:"databases,omitempty"`
	PerDatabase    bool     `json:"per_database"`
}

// MSSQLManifest describes the native SQL Server backup sets of one run
type MSSQLManifest struct {
	Edition        string `json:"edition,omitempty"`
	ProductVersion string `json:"product_version,omitempty"`
	// Mode is the job's mode; every backup set names the type actually taken
	Mode        string           `json:"mode"`
	BackupDir   string           `json:"backup_dir"`
	AgentDir    string           `json:"agent_dir,omitempty"`
	Compression bool             `json:"compression"`
	Checksum    bool             `json:"checksum"`
	CopyOnly    bool             `json:"copy_only,omitempty"`
	BackupSets  []MSSQLBackupSet `json:"backup_sets"`
	// Skipped lists databases that were left out, with the reason
	Skipped []MSSQLSkipped `json:"skipped,omitempty"`
}

// MSSQLBackupSet is one BACKUP DATABASE / BACKUP LOG result as recorded in msdb
type MSSQLBackupSet struct {
	Database string `json:"database"`
	// Type is full, differential or log
	Type          string   `json:"type"`
	RecoveryModel string   `json:"recovery_model,omitempty"`
	Files         []string `json:"files"`
	BackupSetUUID string   `json:"backup_set_uuid,omitempty"`
	FirstLSN      string   `json:"first_lsn,omitempty"`
	LastLSN       string   `json:"last_lsn,omitempty"`
	CheckpointLSN string   `json:"checkpoint_lsn,omitempty"`
	// DatabaseBackupLSN is the checkpoint LSN of the full backup this set builds on
	DatabaseBackupLSN string `json:"database_backup_lsn,omitempty"`
	// DifferentialBaseGUID is the backup_set_uuid of the differential's base full
	DifferentialBaseGUID string    `json:"differential_base_guid,omitempty"`
	StartedAt            time.Time `json:"started_at,omitempty"`
	FinishedAt           time.Time `json:"finished_at,omitempty"`
	BackupBytes          int64     `json:"backup_bytes,omitempty"`
	CompressedBytes      int64     `json:"compressed_bytes,omitempty"`
	// Reason says why this type was chosen (auto mode, chain resets)
	Reason string `json:"reason,omitempty"`
}

// MSSQLSkipped is a database the run left out
type MSSQLSkipped struct {
	Database string `json:"database"`
	Reason   string `json:"reason"`
}

// Restore carries a human-readable summary and ready-to-run commands
type Restore struct {
	Summary  string   `json:"summary"`
	Commands []string `json:"commands"`
}

// Marshal renders the manifest as indented JSON
func (m *Manifest) Marshal() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

// ParseManifest decodes a manifest
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// JobState is persisted per job on the agent after every successful run
type JobState struct {
	JobID       string          `json:"job_id"`
	Engine      string          `json:"engine"`
	LastSuccess *JobStateRecord `json:"last_success,omitempty"`
}

type JobStateRecord struct {
	RunID       string         `json:"run_id"`
	Snapshot    string         `json:"snapshot"`
	CompletedAt time.Time      `json:"completed_at"`
	MySQL       *MySQLState    `json:"mysql,omitempty"`
	Postgres    *PostgresState `json:"postgres,omitempty"`
	MSSQL       *MSSQLState    `json:"mssql,omitempty"`
}

// MSSQLState is the backup chain FallBCK holds per database: the last full, the last
// differential on top of it and the log backups taken since, so a later run can tell
// whether a differential or log backup would still restore from FallBCK's snapshots
type MSSQLState struct {
	Databases map[string]*MSSQLDBState `json:"databases"`
}

// MSSQLDBState is one database's chain
type MSSQLDBState struct {
	RecoveryModel string          `json:"recovery_model,omitempty"`
	LastFull      *MSSQLBackupRef `json:"last_full,omitempty"`
	LastDiff      *MSSQLBackupRef `json:"last_diff,omitempty"`
	// Logs are the log backups since the newest full or differential, oldest first
	Logs []MSSQLBackupRef `json:"logs,omitempty"`
}

// MSSQLBackupRef points at a backup set inside an earlier snapshot
type MSSQLBackupRef struct {
	RunID         string    `json:"run_id"`
	Snapshot      string    `json:"snapshot"`
	Files         []string  `json:"files"`
	BackupSetUUID string    `json:"backup_set_uuid"`
	FirstLSN      string    `json:"first_lsn,omitempty"`
	LastLSN       string    `json:"last_lsn,omitempty"`
	At            time.Time `json:"at"`
}

type MySQLState struct {
	BinlogFile string `json:"binlog_file"`
	BinlogPos  int64  `json:"binlog_pos"`
	GTID       string `json:"gtid,omitempty"`
	ServerID   int64  `json:"server_id,omitempty"`
	ServerUUID string `json:"server_uuid,omitempty"`
}

type PostgresState struct {
	WALEndLSN string `json:"wal_end_lsn,omitempty"`
	Timeline  int64  `json:"timeline,omitempty"`
}
