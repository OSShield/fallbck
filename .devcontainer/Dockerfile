# The Go workspace plus the database client tools the agent looks for, so both dev
# agents can run database jobs. PostgreSQL 17 matches the agent image (pg_dump has to
# be at least as new as the server it dumps); Debian only ships 15, hence PGDG.
# MariaDB's client comes from MariaDB's repository: Debian's 10.11 mariadb-binlog
# can't read binlogs from an 11.x server. mongodb-database-tools only comes from
# MongoDB's.
FROM mcr.microsoft.com/devcontainers/go:1.27-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-common \
 && /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y \
 && curl -fsSL https://mariadb.org/mariadb_release_signing_key.pgp | gpg --dearmor -o /usr/share/keyrings/mariadb.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/mariadb.gpg] https://dlm.mariadb.com/repo/mariadb-server/11.4/repo/debian bookworm main" > /etc/apt/sources.list.d/mariadb.list \
 && curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | gpg --dearmor -o /usr/share/keyrings/mongodb-8.0.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/mongodb-8.0.gpg] https://repo.mongodb.org/apt/debian bookworm/mongodb-org/8.0 main" > /etc/apt/sources.list.d/mongodb-org-8.0.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends postgresql-client-17 mariadb-client mongodb-database-tools \
 && rm -rf /var/lib/apt/lists/*

# SQL Server writes its backup files 0640 as uid/gid 10001; this lets the agent read them
RUN groupadd -g 10001 mssql && usermod -aG mssql vscode
