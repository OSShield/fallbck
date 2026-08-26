#!/bin/sh
set -e
# Only on full removal, not upgrade (deb: "remove", rpm: $1 = 0, apk: always)
case "${1:-}" in
    upgrade|1) exit 0 ;;
esac
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl disable --now fallbck-server >/dev/null 2>&1 || true
elif command -v rc-service >/dev/null 2>&1; then
    rc-service fallbck-server stop >/dev/null 2>&1 || true
    rc-update del fallbck-server default >/dev/null 2>&1 || true
fi
exit 0
