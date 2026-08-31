package dbbackup

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

// querier is the minimal query surface the engines need; tests inject fakes
type querier interface {
	queryRow(ctx context.Context, sql string, dest ...any) error
	// queryRows returns every row as strings (NULL = "")
	queryRows(ctx context.Context, sql string) ([][]string, error)
	close()
}

// quoteLiteral quotes a SQL string literal
func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// ---- PostgreSQL (pgx)

type pgxQuerier struct{ conn *pgx.Conn }

func (q pgxQuerier) queryRow(ctx context.Context, sql string, dest ...any) error {
	return q.conn.QueryRow(ctx, sql).Scan(dest...)
}

func (q pgxQuerier) queryRows(ctx context.Context, sql string) ([][]string, error) {
	rows, err := q.conn.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]string
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, err
		}
		row := make([]string, len(vals))
		for i, v := range vals {
			if v != nil {
				row[i] = fmt.Sprint(v)
			}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (q pgxQuerier) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = q.conn.Close(ctx)
}

func pgQuoteDSN(v string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'"
}

// pgConnect opens a pgx connection with the run's credentials (overridden in tests)
var pgConnect = func(ctx context.Context, creds dbspec.Credentials) (querier, error) {
	parts := []string{
		"host=" + pgQuoteDSN(creds.Host),
		fmt.Sprintf("port=%d", creds.Port),
		"user=" + pgQuoteDSN(creds.User),
		"dbname=postgres",
		"connect_timeout=15",
		"application_name=fallbck-db-agent",
	}
	if creds.TLS.Mode != "" {
		parts = append(parts, "sslmode="+creds.TLS.Mode)
	}
	if creds.TLS.CAFile != "" {
		parts = append(parts, "sslrootcert="+pgQuoteDSN(creds.TLS.CAFile))
	}
	if creds.TLS.CertFile != "" {
		parts = append(parts, "sslcert="+pgQuoteDSN(creds.TLS.CertFile))
	}
	if creds.TLS.KeyFile != "" {
		parts = append(parts, "sslkey="+pgQuoteDSN(creds.TLS.KeyFile))
	}
	cfg, err := pgx.ParseConfig(strings.Join(parts, " "))
	if err != nil {
		return nil, err
	}
	cfg.Password = creds.Password
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return pgxQuerier{conn: conn}, nil
}

// ---- MySQL / MariaDB (database/sql)

type sqlQuerier struct{ db *sql.DB }

func (q sqlQuerier) queryRow(ctx context.Context, query string, dest ...any) error {
	return q.db.QueryRowContext(ctx, query).Scan(dest...)
}

func (q sqlQuerier) queryRows(ctx context.Context, query string) ([][]string, error) {
	rows, err := q.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out [][]string
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make([]string, len(cols))
		for i, v := range vals {
			row[i] = v.String
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (q sqlQuerier) close() { _ = q.db.Close() }

var mysqlTLSSeq atomic.Int64

// mysqlConnect opens a database/sql connection with the run's credentials (overridden in tests)
var mysqlConnect = func(ctx context.Context, creds dbspec.Credentials) (querier, error) {
	mc := mysql.NewConfig()
	mc.User, mc.Passwd = creds.User, creds.Password
	if strings.HasPrefix(creds.Host, "/") {
		mc.Net, mc.Addr = "unix", creds.Host
	} else {
		mc.Net, mc.Addr = "tcp", net.JoinHostPort(creds.Host, fmt.Sprint(creds.Port))
	}
	mc.Timeout = 15 * time.Second
	mc.ReadTimeout = 2 * time.Minute
	switch creds.TLS.Mode {
	case "", dbspec.TLSDisable:
		mc.TLSConfig = "false"
	case dbspec.TLSPrefer:
		mc.TLSConfig = "preferred"
	case dbspec.TLSRequire:
		mc.TLSConfig = "skip-verify"
	case dbspec.TLSVerifyCA, dbspec.TLSVerifyFull:
		tlsCfg := &tls.Config{ServerName: creds.Host, MinVersion: tls.VersionTLS12}
		if creds.TLS.CAFile != "" {
			pem, err := os.ReadFile(creds.TLS.CAFile)
			if err != nil {
				return nil, fmt.Errorf("reading tls.ca_file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("tls.ca_file %s contains no certificates", creds.TLS.CAFile)
			}
			tlsCfg.RootCAs = pool
		}
		if creds.TLS.CertFile != "" && creds.TLS.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(creds.TLS.CertFile, creds.TLS.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("loading client certificate: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		if creds.TLS.Mode == dbspec.TLSVerifyCA {
			// Chain check without hostname verification
			pool := tlsCfg.RootCAs
			tlsCfg.InsecureSkipVerify = true //nolint:gosec // verified in VerifyPeerCertificate
			tlsCfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return fmt.Errorf("server presented no certificate")
				}
				leaf, err := x509.ParseCertificate(raw[0])
				if err != nil {
					return err
				}
				inter := x509.NewCertPool()
				for _, r := range raw[1:] {
					if c, err := x509.ParseCertificate(r); err == nil {
						inter.AddCert(c)
					}
				}
				_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter})
				return err
			}
		}
		name := fmt.Sprintf("fallbck-%d", mysqlTLSSeq.Add(1))
		if err := mysql.RegisterTLSConfig(name, tlsCfg); err != nil {
			return nil, err
		}
		mc.TLSConfig = name
	}
	db, err := sql.Open("mysql", mc.FormatDSN())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return sqlQuerier{db: db}, nil
}
