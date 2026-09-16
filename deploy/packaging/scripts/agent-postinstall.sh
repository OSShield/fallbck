#!/bin/sh
set -e
mkdir -p /var/lib/fallbck/agent /var/log/fallbck
chmod 0700 /var/lib/fallbck/agent
chmod 0600 /etc/fallbck/agent.env

# Runs after the files are unpacked on install and upgrade alike (deb postinst
# "configure", rpm %post, apk post-install/post-upgrade). A service that is running
# still executes the old binary, so restart it; a fresh install has nothing running
# and gets the enrollment hint instead. A failed restart must not fail the package.
svc=fallbck-agent
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    case "$(systemctl is-active "$svc" 2>/dev/null || true)" in
        active|activating|reloading)
            echo "Restarting $svc to load the upgraded binary"
            systemctl restart "$svc" || echo "WARNING: $svc failed to restart; see: journalctl -u $svc" >&2
            ;;
        *)
            echo "$svc installed. Enroll with:"
            echo "  fallbck-agent enroll --server https://backup.example.com --token <token>"
            echo "then: systemctl enable --now $svc"
            ;;
    esac
elif command -v rc-service >/dev/null 2>&1; then
    if rc-service "$svc" status >/dev/null 2>&1; then
        echo "Restarting $svc to load the upgraded binary"
        rc-service "$svc" restart || echo "WARNING: $svc failed to restart; see: /var/log/fallbck/agent.log" >&2
    else
        echo "$svc installed. Enroll with:"
        echo "  fallbck-agent enroll --server https://backup.example.com --token <token>"
        echo "then: rc-update add $svc default && rc-service $svc start"
    fi
fi
exit 0
