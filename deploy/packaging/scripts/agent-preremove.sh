#!/bin/sh
set -e
case "${1:-}" in
    upgrade|1) exit 0 ;;
esac
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl disable --now fallbck-agent >/dev/null 2>&1 || true
elif command -v rc-service >/dev/null 2>&1; then
    rc-service fallbck-agent stop >/dev/null 2>&1 || true
    rc-update del fallbck-agent default >/dev/null 2>&1 || true
fi
exit 0
