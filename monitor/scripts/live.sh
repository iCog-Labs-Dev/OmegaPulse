#!/usr/bin/env bash
# Start the monitor separately from Oma; no provider or Telegram keys are needed.
set -euo pipefail
set +x
monitor_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
events_dir="${OMA_MONITOR_EVENTS_DIR:-$monitor_dir/.local/falco-events}"
container="${OMA_MONITOR_DOCKER_NAME:-oma-monitor-live}"
target="${OMA_MONITOR_CONTAINER:-omega}"
[[ "$container" != "$target" ]] || { printf 'Monitor and Oma container names must differ.\n' >&2; exit 1; }

is_monitor() {
    local metadata
    metadata="$(docker inspect --format '{{ index .Config.Labels "oma.monitor.component" }} {{ index .Config.Labels "oma.monitor.live" }} {{json .Config.Cmd}}' "$container")"
    [[ "$metadata" == monitor\ * || "$metadata" == *' local-test ["python","-m","monitor.app"]' ]]
}

case "${1:-start}" in
    signals)
        marker="oma-monitor-check-$(date +%s)"
        docker exec -i -u 65534:65534 "$target" sh -c \
            'python3 - "$1" token=demo-secret' sh "$marker" \
            < "$monitor_dir/tests/omega_runtime_indicators.py"
        printf 'Find %s in the browser security signals.\n' "$marker"
        exit 0 ;;
    stop|resume)
        is_monitor || { printf 'Existing container is not a managed monitor.\n' >&2; exit 1; }
        action=stop
        [[ "$1" == stop ]] || action=start
        docker "$action" "$container"
        exit 0 ;;
    start|monitor|users) ;;
    *) printf 'Usage: bash monitor/scripts/live.sh start|monitor|signals|stop|resume|users\n' >&2; exit 1 ;;
esac

docker info >/dev/null
umask 077
auth_dir="${OMA_MONITOR_AUTH_DIR:-$monitor_dir/.local/auth}"
mkdir -p "$events_dir" "$auth_dir"
events_dir="$(cd -- "$events_dir" && pwd)"
auth_dir="$(cd -- "$auth_dir" && pwd)"
docker build -t oma-monitor:local "$monitor_dir"
user_args=(--user "$(id -u):$(id -g)" --mount "type=bind,src=$auth_dir,dst=/auth" -e OMA_MONITOR_AUTH_DB=/auth/users.sqlite3)
if [[ "${1:-}" == users ]]; then
    shift
    docker run --rm -it "${user_args[@]}" --entrypoint python oma-monitor:local -m monitor.users "$@"
    exit 0
fi
if ! docker run --rm "${user_args[@]}" --entrypoint python oma-monitor:local -c \
    'from monitor.auth import AuthStore; from pathlib import Path; raise SystemExit(0 if AuthStore(Path("/auth/users.sqlite3")).users() else 1)'; then
    read -r -p 'Initial individual operator username: ' username
    docker run --rm -it "${user_args[@]}" --entrypoint python oma-monitor:local -m monitor.users add "$username" --role operator
fi
export OMA_MONITOR_AUTH_DB=/auth/users.sqlite3 OMA_MONITOR_CONTAINER="$target" OMA_MONITOR_HOST=127.0.0.1
export OMA_MONITOR_COOKIE_SECURE=false OMA_MONITOR_PORT="${OMA_MONITOR_PORT:-8765}"
export OMA_MONITOR_SECURITY_EVENTS_FILE=/events/oma-events.jsonl
docker run --rm "${user_args[@]}" -e OMA_MONITOR_CONTAINER -e OMA_MONITOR_HOST \
    -e OMA_MONITOR_PORT -e OMA_MONITOR_COOKIE_SECURE --entrypoint python oma-monitor:local -c \
    'from monitor.config import MonitorConfig; MonitorConfig.from_env()'
if docker container inspect "$container" >/dev/null 2>&1; then
    is_monitor || { printf 'Existing container is not a managed monitor.\n' >&2; exit 1; }
    docker stop "$container" >/dev/null
    docker rename "$container" "$container-backup-$(date +%Y%m%d-%H%M%S)"
fi
docker run -d --name "$container" --label oma.monitor.component=monitor \
    "${user_args[@]}" --group-add "$(stat -c '%g' /var/run/docker.sock)" \
    --network host --init --security-opt no-new-privileges:true \
    -e OMA_MONITOR_CONTAINER -e OMA_MONITOR_HOST -e OMA_MONITOR_PORT -e OMA_MONITOR_COOKIE_SECURE \
    -e OMA_MONITOR_SECURITY_EVENTS_FILE \
    --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock \
    --mount "type=bind,src=$events_dir,dst=/events,readonly" oma-monitor:local
printf 'Monitor: http://127.0.0.1:%s/\n' "$OMA_MONITOR_PORT"
