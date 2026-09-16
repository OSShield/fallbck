#!/bin/sh
set -e
# Ownership is recorded in the package itself; this only repairs pre-existing dirs
mkdir -p /var/lib/fallbck/server /var/log/fallbck
chown fallbck:fallbck /var/lib/fallbck/server /var/log/fallbck
chmod 0750 /var/lib/fallbck/server /var/log/fallbck
chown root:fallbck /etc/fallbck/server.yaml /etc/fallbck/server.env
chmod 0640 /etc/fallbck/server.yaml /etc/fallbck/server.env

# Runs after the files are unpacked on install and upgrade alike (deb postinst
# "configure", rpm %post, apk post-install/post-upgrade). A service that is running
# still executes the old binary, so restart it; a fresh install has nothing running
# and gets the configuration hint instead. A failed restart must not fail the package.
svc=fallbck-server
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    case "$(systemctl is-active "$svc" 2>/dev/null || true)" in
        active|activating|reloading)
            echo "Restarting $svc to load the upgraded binary"
            systemctl restart "$svc" || echo "WARNING: $svc failed to restart; see: journalctl -u $svc" >&2
            ;;
        *)
            echo "$svc installed. Edit /etc/fallbck/server.yaml, then:"
            echo "  systemctl enable --now $svc"
            ;;
    esac
elif command -v rc-service >/dev/null 2>&1; then
    if rc-service "$svc" status >/dev/null 2>&1; then
        echo "Restarting $svc to load the upgraded binary"
        rc-service "$svc" restart || echo "WARNING: $svc failed to restart; see: /var/log/fallbck/server.log" >&2
    else
        echo "$svc installed. Edit /etc/fallbck/server.yaml, then:"
        echo "  rc-update add $svc default && rc-service $svc start"
    fi
fi
exit 0
