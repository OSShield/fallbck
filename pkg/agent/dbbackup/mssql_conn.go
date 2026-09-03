package dbbackup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/golang-sql/sqlexp"
	_ "github.com/microsoft/go-mssqldb" // registers the "sqlserver" database/sql driver
	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

// mssqlConn is the connection surface of the SQL Server engine: the shared querier
// plus exec, which runs a statement to completion and hands the server's informational
// messages (BACKUP progress) to onMessage; tests inject fakes
type mssqlConn interface {
	querier
	exec(ctx context.Context, query string, onMessage func(string)) error
}

type mssqlQuerier struct{ sqlQuerier }

// exec drains every result and message of the batch. BACKUP reports failures as
// messages after the statement was accepted, so a plain ExecContext would miss them.
func (q mssqlQuerier) exec(ctx context.Context, query string, onMessage func(string)) error {
	retmsg := &sqlexp.ReturnMessage{}
	rows, err := q.db.QueryContext(ctx, query, retmsg)
	if err != nil {
		return err
	}
	defer rows.Close()
	var failures []string
	for active := true; active; {
		switch m := retmsg.Message(ctx).(type) {
		case sqlexp.MsgNotice:
			if onMessage != nil {
				onMessage(m.Message.String())
			}
		case sqlexp.MsgError:
			failures = append(failures, m.Error.Error())
		case sqlexp.MsgNext:
			for rows.Next() {
			}
		case sqlexp.MsgNextResultSet:
			active = rows.NextResultSet()
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return ctx.Err()
}

// mssqlDSN builds the sqlserver:// URL. "host\instance" selects a named instance
// (resolved through the SQL Server Browser unless a non-default port is given); a
// blank user means Windows integrated authentication.
func mssqlDSN(creds dbspec.Credentials) string {
	host, instance, _ := strings.Cut(creds.Host, `\`)
	u := &url.URL{Scheme: "sqlserver", Host: host}
	if instance != "" {
		u.Path = "/" + instance
	}
	if creds.Port != 0 && (instance == "" || creds.Port != dbspec.DefaultPort(dbspec.EngineMSSQL)) {
		u.Host = fmt.Sprintf("%s:%d", host, creds.Port)
	}
	if creds.User != "" {
		u.User = url.UserPassword(creds.User, creds.Password)
	}
	q := url.Values{}
	q.Set("database", "master")
	q.Set("app name", "fallbck-agent")
	q.Set("connection timeout", "0") // backups run for hours; the context bounds them
	q.Set("dial timeout", "15")
	switch creds.TLS.Mode {
	case dbspec.TLSDisable:
		q.Set("encrypt", "disable")
	case "", dbspec.TLSPrefer:
		// The login is protected by TLS even without full encryption, and the driver
		// verifies the certificate for it: SQL Server's default self-signed certificate
		// would fail every connection, so only the verify modes check it
		q.Set("encrypt", "false")
		q.Set("TrustServerCertificate", "true")
	case dbspec.TLSRequire:
		q.Set("encrypt", "true")
		q.Set("TrustServerCertificate", "true")
	case dbspec.TLSVerifyCA, dbspec.TLSVerifyFull:
		// The driver always checks the host name along with the chain
		q.Set("encrypt", "true")
		q.Set("TrustServerCertificate", "false")
		if creds.TLS.CAFile != "" {
			q.Set("certificate", creds.TLS.CAFile)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// mssqlConnect opens the connection with the run's credentials (overridden in tests)
var mssqlConnect = func(ctx context.Context, creds dbspec.Credentials) (mssqlConn, error) {
	db, err := sql.Open("sqlserver", mssqlDSN(creds))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return mssqlQuerier{sqlQuerier{db: db}}, nil
}
