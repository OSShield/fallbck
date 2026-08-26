#!/bin/sh
set -e
# Ownership is recorded in the package itself; this only repairs pre-existing dirs
mkdir -p /var/lib/fallbck/server /var/log/fallbck
chown fallbck:fallbck /var/lib/fallbck/server /var/log/fallbck
chmod 0750 /var/lib/fallbck/server /var/log/fallbck
chown root:fallbck /etc/fallbck/server.yaml /etc/fallbck/server.env
chmod 0640 /etc/fallbck/server.yaml /etc/fallbck/server.env

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    echo "fallbck-server installed. Edit /etc/fallbck/server.yaml, then:"
    echo "  systemctl enable --now fallbck-server"
elif command -v rc-update >/dev/null 2>&1; then
    echo "fallbck-server installed. Edit /etc/fallbck/server.yaml, then:"
    echo "  rc-update add fallbck-server default && rc-service fallbck-server start"
fi
exit 0
