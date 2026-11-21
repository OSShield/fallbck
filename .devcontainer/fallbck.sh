#!/usr/bin/env bash
# Builds the server and the agent from this checkout and (re)starts them in the
# background: the server, the agent fallbck-dev (files, databases) and, when the
# Docker socket is mounted, fallbck-dev-docker (Docker host, as root like on a real
# host). A build error leaves the running ones alone.
#
#   .devcontainer/fallbck.sh          build and restart everything
#   .devcontainer/fallbck.sh stop     stop everything
#   .devcontainer/fallbck.sh logs     follow the logs
set -euo pipefail
cd "$(dirname "$0")/.."

run=/var/lib/fallbck/run # binaries and logs
token=12345678-1234-1234-1234-1234567890ab # enrollment token, same as the demo

stop() {
  pkill -x fallbck-server || true
  sudo pkill -x fallbck-agent || true
  while pgrep -x fallbck-server >/dev/null || pgrep -x fallbck-agent >/dev/null; do sleep 0.2; done
}

case "${1:-start}" in
stop)
  stop
  exit
  ;;
logs) exec tail -F "$run"/*.log ;;
start) ;;
*)
  echo "usage: $0 [start|stop|logs]" >&2
  exit 2
  ;;
esac

mkdir -p "$run"
echo "Building..."
go build -o "$run/fallbck-server.new" ./cmd/fallbck-server
go build -o "$run/fallbck-agent.new" ./cmd/fallbck-agent
stop
mv "$run/fallbck-server.new" "$run/fallbck-server"
mv "$run/fallbck-agent.new" "$run/fallbck-agent"

# No auth, the demo's enrollment token and its PBS as a target. The master key and
# JWT secret are generated into the data dir on first start.
FALLBCK_DB_URL='postgres://fallbck:fallbck@postgres:5432/fallbck?sslmode=disable' \
  FALLBCK_DATA_DIR=/var/lib/fallbck/server \
  FALLBCK_HTTP_PORT=8080 \
  FALLBCK_PUBLIC_URL=http://localhost:8080 \
  FALLBCK_TEMPORAL_MODE=embedded \
  FALLBCK_AUTH_INSECURE_DISABLE=true \
  setsid nohup "$run/fallbck-server" --dev \
  --insecure-unlimited-dev-token="$token" \
  --dev-create-remote='Demo Level1' \
  --dev-remote-url=https://pbs:8007 \
  --dev-remote-datastore=data \
  --dev-remote-namespace=level1 \
  --dev-remote-token="backupuser@pbs!backup:$token" \
  --dev-remote-verify-none \
  >"$run/server.log" 2>&1 </dev/null &

echo "Waiting for the server..."
for _ in $(seq 120); do
  curl -fs http://localhost:8080/api/v1/health >/dev/null && break
  sleep 1
done
curl -fs http://localhost:8080/api/v1/health >/dev/null || {
  echo "The server didn't come up; tail of $run/server.log:" >&2
  tail -20 "$run/server.log" >&2
  exit 1
}

FALLBCK_AGENT_SERVER_URL=http://localhost:8080 \
  FALLBCK_AGENT_ENROLLMENT_KEY="$token" \
  FALLBCK_AGENT_DATA_DIR=/var/lib/fallbck/agent \
  setsid nohup "$run/fallbck-agent" run >"$run/agent.log" 2>&1 </dev/null &

agents=fallbck-dev
if [ -S /var/run/docker.sock ]; then
  sudo env FALLBCK_AGENT_SERVER_URL=http://localhost:8080 \
    FALLBCK_AGENT_ENROLLMENT_KEY="$token" \
    FALLBCK_AGENT_DATA_DIR=/var/lib/fallbck/docker-agent \
    FALLBCK_AGENT_HOSTNAME=fallbck-dev-docker \
    setsid nohup "$run/fallbck-agent" run >"$run/docker-agent.log" 2>&1 </dev/null &
  agents="$agents, fallbck-dev-docker"
fi

echo "FallBCK: http://localhost:8080 (agents $agents). Logs: $0 logs"
