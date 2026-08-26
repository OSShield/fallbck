#!/bin/sh
set -e
mkdir -p /var/lib/fallbck/agent /var/log/fallbck
chmod 0700 /var/lib/fallbck/agent
chmod 0600 /etc/fallbck/agent.env

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    echo "fallbck-agent installed. Enroll with:"
    echo "  fallbck-agent enroll --server https://backup.example.com --token <token>"
    echo "then: systemctl enable --now fallbck-agent"
elif command -v rc-update >/dev/null 2>&1; then
    echo "fallbck-agent installed. Enroll with:"
    echo "  fallbck-agent enroll --server https://backup.example.com --token <token>"
    echo "then: rc-update add fallbck-agent default && rc-service fallbck-agent start"
fi
exit 0
