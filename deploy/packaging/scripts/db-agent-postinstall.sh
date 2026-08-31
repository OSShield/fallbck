#!/bin/sh
set -e
mkdir -p /var/lib/fallbck/db-agent /var/log/fallbck
chown fallbck:fallbck /var/lib/fallbck/db-agent /var/log/fallbck
chmod 0700 /var/lib/fallbck/db-agent
chmod 0600 /etc/fallbck/db-agent.env

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    echo "fallbck-db-agent installed. Enroll with:"
    echo "  fallbck-db-agent enroll --server https://backup.example.com --token <token>"
    echo "then: fallbck-db-agent tools && systemctl enable --now fallbck-db-agent"
elif command -v rc-update >/dev/null 2>&1; then
    echo "fallbck-db-agent installed. Enroll with:"
    echo "  fallbck-db-agent enroll --server https://backup.example.com --token <token>"
    echo "then: fallbck-db-agent tools && rc-update add fallbck-db-agent default && rc-service fallbck-db-agent start"
fi
echo "Database client tools are not part of this package: install postgresql-client / mariadb-client (or mysql-client) / mongodb-database-tools as needed."
exit 0
