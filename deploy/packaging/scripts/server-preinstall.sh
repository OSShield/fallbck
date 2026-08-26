#!/bin/sh
set -e
if ! getent group fallbck >/dev/null 2>&1; then
    if command -v addgroup >/dev/null 2>&1 && [ -f /etc/alpine-release ]; then
        addgroup -S fallbck
    else
        groupadd --system fallbck
    fi
fi
if ! getent passwd fallbck >/dev/null 2>&1; then
    if command -v adduser >/dev/null 2>&1 && [ -f /etc/alpine-release ]; then
        adduser -S -D -H -h /var/lib/fallbck/server -s /sbin/nologin -G fallbck -g "FallBCK server" fallbck
    else
        useradd --system --no-create-home --home-dir /var/lib/fallbck/server --shell /sbin/nologin --gid fallbck --comment "FallBCK server" fallbck
    fi
fi
exit 0
