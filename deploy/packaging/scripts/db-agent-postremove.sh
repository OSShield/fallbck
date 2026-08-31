#!/bin/sh
set -e
case "${1:-}" in
    upgrade|1) exit 0 ;;
esac
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
# /var/lib/fallbck/db-agent (enrollment + token) is kept on purpose
exit 0
