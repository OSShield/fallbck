#!/bin/sh
set -e
case "${1:-}" in
    upgrade|1) exit 0 ;;
esac
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
# Data in /var/lib/fallbck/server and the fallbck user are kept on purpose
exit 0
