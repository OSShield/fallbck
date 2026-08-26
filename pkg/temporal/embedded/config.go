// Package embedded runs the Temporal server in-process inside fallbck-server.
//
// All Temporal services (frontend, internal-frontend, history, matching, worker) bind to
// a loopback address; nothing here is reachable from outside the host. Agents reach the
// frontend only through the authenticating gateway on the public port.
package embedded

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.temporal.io/server/common/cluster"
	"go.temporal.io/server/common/config"
	"go.temporal.io/server/common/primitives"
)

// Persistence selects the backing store of the embedded server
type Persistence string

const (
	// PersistencePostgres stores Temporal state in PostgreSQL (production)
	PersistencePostgres Persistence = "postgres"
	// PersistenceSQLite stores state in an in-memory or file SQLite database (tests only;
	// requires the `sqlite` build tag)
	PersistenceSQLite Persistence = "sqlite"
)

// Default values for Config
const (
	DefaultBindIP             = "127.0.0.1"
	DefaultPortBase           = 7233
	DefaultHistoryShards      = 4
	DefaultRetention          = 72 * time.Hour
	DefaultStopTimeout        = 30 * time.Second
	DefaultClusterName        = "fallbck"
	DefaultNamespace          = "default"
	DefaultTemporalDatabase   = "temporal"
	DefaultVisibilityDatabase = "temporal_visibility"
	PostgresPluginName        = "postgres12_pgx"
)

// Config describes the embedded Temporal deployment
type Config struct {
	// BindIP is the loopback address every Temporal service listens on
	BindIP string
	// PortBase is the frontend gRPC port; the other services use PortBase+1..+6 and
	// membership ports PortBase-300+n (7233 → 6933…)
	PortBase int
	// Persistence selects postgres (default) or sqlite (tests)
	Persistence Persistence
	// DatabaseURL is a postgres:// URL; the database in its path is ignored and replaced
	// with TemporalDatabase / VisibilityDatabase
	DatabaseURL string
	// TemporalDatabase and VisibilityDatabase are the two Postgres databases Temporal needs
	TemporalDatabase   string
	VisibilityDatabase string
	// SQLiteFile is the database file for sqlite persistence; empty = in-memory
	SQLiteFile string
	// HistoryShards is immutable after the first start (persisted in cluster metadata)
	HistoryShards int32
	// Namespace is registered on first start with Retention
	Namespace string
	Retention time.Duration
	// ClusterName is immutable after the first start
	ClusterName string
	// DataDir persists the generated cluster ID; empty = random per start (tests)
	DataDir string
	// StopTimeout bounds Stop(): Temporal's own shutdown can wait minutes for system
	// worker long polls to drain; after this the shutdown continues in the background.
	StopTimeout time.Duration
}

// withDefaults fills unset fields
func (c Config) withDefaults() Config {
	if c.BindIP == "" {
		c.BindIP = DefaultBindIP
	}
	if c.PortBase == 0 {
		c.PortBase = DefaultPortBase
	}
	if c.Persistence == "" {
		c.Persistence = PersistencePostgres
	}
	if c.TemporalDatabase == "" {
		c.TemporalDatabase = DefaultTemporalDatabase
	}
	if c.VisibilityDatabase == "" {
		c.VisibilityDatabase = DefaultVisibilityDatabase
	}
	if c.HistoryShards == 0 {
		c.HistoryShards = DefaultHistoryShards
	}
	if c.Namespace == "" {
		c.Namespace = DefaultNamespace
	}
	if c.Retention == 0 {
		c.Retention = DefaultRetention
	}
	if c.ClusterName == "" {
		c.ClusterName = DefaultClusterName
	}
	if c.StopTimeout == 0 {
		c.StopTimeout = DefaultStopTimeout
	}
	return c
}

// Validate checks the configuration
func (c Config) Validate() error {
	c = c.withDefaults()
	if net.ParseIP(c.BindIP) == nil {
		return fmt.Errorf("temporal.embedded.bind_ip %q is not an IP address", c.BindIP)
	}
	if c.PortBase < 1024 || c.PortBase+6 > 65535 || c.PortBase-300 < 1 {
		return fmt.Errorf("temporal.embedded.port_base %d is out of range", c.PortBase)
	}
	switch c.Persistence {
	case PersistencePostgres:
		if c.DatabaseURL == "" {
			return errors.New("temporal.embedded.database_url is required")
		}
		if _, err := c.postgresSQLConfig(""); err != nil {
			return err
		}
	case PersistenceSQLite:
	default:
		return fmt.Errorf("unknown temporal persistence %q", c.Persistence)
	}
	if c.HistoryShards < 1 {
		return errors.New("temporal.embedded.history_shards must be >= 1")
	}
	return nil
}

// servicePorts returns the gRPC and membership ports for each service
type servicePorts struct {
	grpc       int
	membership int
}

func (c Config) ports() map[primitives.ServiceName]servicePorts {
	base := c.PortBase
	offsets := map[primitives.ServiceName]int{
		primitives.FrontendService:         0,
		primitives.HistoryService:          1,
		primitives.MatchingService:         2,
		primitives.InternalFrontendService: 3,
		primitives.WorkerService:           6,
	}
	out := make(map[primitives.ServiceName]servicePorts, len(offsets))
	for svc, off := range offsets {
		out[svc] = servicePorts{grpc: base + off, membership: base - 300 + off}
	}
	return out
}

// FrontendAddr is the loopback address of the public-facing (but loopback-bound) frontend
func (c Config) FrontendAddr() string {
	c = c.withDefaults()
	return net.JoinHostPort(c.BindIP, strconv.Itoa(c.ports()[primitives.FrontendService].grpc))
}

// services lists the Temporal services run in-process
func services() []string {
	return []string{
		string(primitives.FrontendService),
		string(primitives.InternalFrontendService),
		string(primitives.HistoryService),
		string(primitives.MatchingService),
		string(primitives.WorkerService),
	}
}

// postgresSQLConfig translates DatabaseURL into Temporal's SQL config for database dbName.
// Passing "" leaves DatabaseName empty (used for validation and server-level connections).
func (c Config) postgresSQLConfig(dbName string) (*config.SQL, error) {
	u, err := url.Parse(c.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("temporal.embedded.database_url is not a valid URL: %w", err)
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return nil, fmt.Errorf("temporal.embedded.database_url must be a postgres:// URL, got scheme %q", u.Scheme)
	}
	host := u.Hostname()
	port := u.Port()
	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = "5432"
	}
	password, _ := u.User.Password()

	attrs := map[string]string{}
	for k, vals := range u.Query() {
		if len(vals) > 0 {
			attrs[k] = vals[0]
		}
	}

	return &config.SQL{
		PluginName:        PostgresPluginName,
		DatabaseName:      dbName,
		ConnectAddr:       net.JoinHostPort(host, port),
		ConnectProtocol:   "tcp",
		User:              u.User.Username(),
		Password:          password,
		ConnectAttributes: attrs,
		MaxConns:          20,
		MaxIdleConns:      20,
		MaxConnLifetime:   time.Hour,
	}, nil
}

// clusterID returns the persisted cluster ID, generating and storing it on first start
func (c Config) clusterID() (string, error) {
	if c.DataDir == "" {
		return uuid.NewString(), nil
	}
	path := filepath.Join(c.DataDir, "temporal-cluster-id")
	if data, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			return id, nil
		}
	}
	if err := os.MkdirAll(c.DataDir, 0o750); err != nil {
		return "", fmt.Errorf("failed to create data dir %s: %w", c.DataDir, err)
	}
	id := uuid.NewString()
	if err := os.WriteFile(path, []byte(id+"\n"), 0o640); err != nil {
		return "", fmt.Errorf("failed to persist temporal cluster id: %w", err)
	}
	return id, nil
}

// buildServerConfig produces the Temporal server configuration for a single-process cluster
func (c Config) buildServerConfig(dataStores map[string]config.DataStore, defaultStore, visibilityStore string) (*config.Config, error) {
	clusterID, err := c.clusterID()
	if err != nil {
		return nil, err
	}

	conf := &config.Config{}
	conf.Global.Membership.MaxJoinDuration = 30 * time.Second
	conf.Global.Membership.BroadcastAddress = c.BindIP

	conf.Persistence.DefaultStore = defaultStore
	conf.Persistence.VisibilityStore = visibilityStore
	conf.Persistence.NumHistoryShards = c.HistoryShards
	conf.Persistence.DataStores = dataStores

	conf.ClusterMetadata = &cluster.Config{
		EnableGlobalNamespace:    false,
		FailoverVersionIncrement: 10,
		MasterClusterName:        c.ClusterName,
		CurrentClusterName:       c.ClusterName,
		ClusterInformation: map[string]cluster.ClusterInformation{
			c.ClusterName: {
				Enabled:                true,
				InitialFailoverVersion: 1,
				RPCAddress:             c.FrontendAddr(),
				ClusterID:              clusterID,
			},
		},
	}
	conf.DCRedirectionPolicy.Policy = "noop"

	conf.Services = map[string]config.Service{}
	for svc, p := range c.ports() {
		conf.Services[string(svc)] = config.Service{RPC: config.RPC{
			GRPCPort:       p.grpc,
			MembershipPort: p.membership,
			BindOnIP:       c.BindIP,
			HTTPPort:       0,
		}}
	}

	conf.Archival.History.State = "disabled"
	conf.Archival.Visibility.State = "disabled"
	conf.NamespaceDefaults.Archival.History.State = "disabled"
	conf.NamespaceDefaults.Archival.Visibility.State = "disabled"
	// PublicClient must stay empty: with internal-frontend configured the system worker
	// resolves the internal frontend through membership.

	return conf, nil
}
