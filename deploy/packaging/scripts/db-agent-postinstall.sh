#!/bin/sh
set -e
mkdir -p /var/lib/fallbck/db-agent /var/log/fallbck
chown fallbck:fallbck /var/lib/fallbck/db-agent /var/log/fallbck
chmod 0700 /var/lib/fallbck/db-agent
chmod 0600 /etc/fallbck/db-agent.env

# Runs after the files are unpacked on install and upgrade alike (deb postinst
# "configure", rpm %post, apk post-install/post-upgrade). A service that is running
# still executes the old binary, so restart it; a fresh install has nothing running
# and gets the enrollment hint instead. A failed restart must not fail the package.
svc=fallbck-db-agent
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    case "$(systemctl is-active "$svc" 2>/dev/null || true)" in
        active|activating|reloading)
            echo "Restarting $svc to load the upgraded binary"
            systemctl restart "$svc" || echo "WARNING: $svc failed to restart; see: journalctl -u $svc" >&2
            ;;
        *)
            echo "$svc installed. Enroll with:"
            echo "  fallbck-db-agent enroll --server https://backup.example.com --token <token>"
            echo "then: fallbck-db-agent tools && systemctl enable --now $svc"
            ;;
    esac
elif command -v rc-service >/dev/null 2>&1; then
    if rc-service "$svc" status >/dev/null 2>&1; then
        echo "Restarting $svc to load the upgraded binary"
        rc-service "$svc" restart || echo "WARNING: $svc failed to restart; see: /var/log/fallbck/db-agent.log" >&2
    else
        echo "$svc installed. Enroll with:"
        echo "  fallbck-db-agent enroll --server https://backup.example.com --token <token>"
        echo "then: fallbck-db-agent tools && rc-update add $svc default && rc-service $svc start"
    fi
fi
echo "Database client tools are not part of this package: install postgresql-client / mariadb-client (or mysql-client) / mongodb-database-tools as needed."
exit 0
