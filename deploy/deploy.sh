#!/usr/bin/env bash
# Deploy an Omega Pulse container image on a server with health check and automatic rollback.
# Usage: bash deploy/deploy.sh <env-file> <image>
set -euo pipefail
set +x

if [[ $# -ne 2 ]]; then
    printf 'Usage: %s <env-file> <image>\n' "$0" >&2
    exit 1
fi

env_file="$1"
image="$2"

if [[ ! -f "$env_file" ]]; then
    printf 'Environment file not found: %s\n' "$env_file" >&2
    exit 1
fi

deploy_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$deploy_dir/.." && pwd)"
monitor_dir="$repo_root/monitor"

set -a
# shellcheck source=/dev/null
source "$env_file"
set +a

container="${OMA_MONITOR_DOCKER_NAME:-oma-monitor-live}"
target="${OMA_MONITOR_CONTAINER:-omega}"
[[ "$container" != "$target" ]] || { printf 'Monitor and Oma container names must differ.\n' >&2; exit 1; }

is_monitor() {
    local metadata
    metadata="$(docker inspect --format '{{ index .Config.Labels "oma.monitor.component" }} {{ index .Config.Labels "oma.monitor.live" }} {{json .Config.Cmd}}' "$container")"
    [[ "$metadata" == monitor\ * || "$metadata" == *' local-test ["python","-m","monitor.app"]' ]]
}

docker info >/dev/null

# 1. Pull the image.
printf 'Pulling %s...\n' "$image"
docker pull "$image"

expected_version="$(docker inspect --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' "$image" 2>/dev/null || true)"
if [[ -z "$expected_version" ]]; then
    expected_version="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$image" | sed -n 's/^PULSE_VERSION=//p' | head -n 1 || true)"
fi
image_digest="$(docker inspect --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}' "$image" 2>/dev/null || printf 'unknown')"

# 2. Check the config with MonitorConfig.from_env(), as live.sh does.
umask 077
events_dir="${OMA_MONITOR_EVENTS_DIR:-$monitor_dir/.local/falco-events}"
auth_dir="${OMA_MONITOR_AUTH_DIR:-$monitor_dir/.local/auth}"
mkdir -p "$events_dir" "$auth_dir"
events_dir="$(cd -- "$events_dir" && pwd)"
auth_dir="$(cd -- "$auth_dir" && pwd)"

user_args=(--user "$(id -u):$(id -g)" --mount "type=bind,src=$auth_dir,dst=/auth" -e OMA_MONITOR_AUTH_DB=/auth/users.sqlite3)

export OMA_MONITOR_AUTH_DB=/auth/users.sqlite3
export OMA_MONITOR_CONTAINER="$target"
export OMA_MONITOR_HOST=127.0.0.1
export OMA_MONITOR_COOKIE_SECURE="${OMA_MONITOR_COOKIE_SECURE:-true}"
export OMA_MONITOR_PORT="${OMA_MONITOR_PORT:-8765}"
export OMA_MONITOR_SECURITY_EVENTS_FILE=/events/oma-events.jsonl

docker run --rm "${user_args[@]}" \
    -e OMA_MONITOR_CONTAINER -e OMA_MONITOR_HOST \
    -e OMA_MONITOR_PORT -e OMA_MONITOR_COOKIE_SECURE \
    --entrypoint python "$image" -c \
    'from monitor.config import MonitorConfig; MonitorConfig.from_env()'

# 3. Stop the running monitor and rename it to a backup, as live.sh does.
backup_name=""
if docker container inspect "$container" >/dev/null 2>&1; then
    is_monitor || { printf 'Existing container %s is not a managed monitor.\n' "$container" >&2; exit 1; }
    backup_name="$container-backup-$(date +%Y%m%d-%H%M%S)"
    docker stop "$container" >/dev/null
    docker rename "$container" "$backup_name"
fi

# 4. Start the new container with the same mounts, user, group, labels, and security options.
rollback() {
    printf 'Deploy health check failed; rolling back...\n' >&2
    docker logs --tail 50 "$container" >&2 || true
    docker rm -f "$container" >/dev/null 2>&1 || true
    if [[ -n "$backup_name" ]]; then
        docker rename "$backup_name" "$container"
        docker start "$container" >/dev/null
        printf 'Rolled back to %s.\n' "$backup_name" >&2
    fi
}

if ! docker run -d --name "$container" --restart unless-stopped --label oma.monitor.component=monitor \
    "${user_args[@]}" --group-add "$(stat -c '%g' /var/run/docker.sock)" \
    --network host --init --security-opt no-new-privileges:true \
    -e OMA_MONITOR_CONTAINER -e OMA_MONITOR_HOST -e OMA_MONITOR_PORT -e OMA_MONITOR_COOKIE_SECURE \
    -e OMA_MONITOR_SECURITY_EVENTS_FILE \
    --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock \
    --mount "type=bind,src=$events_dir,dst=/events,readonly" "$image"; then
    rollback
    exit 1
fi

# 5. Call /healthz for up to 30 seconds and check the version matches.
health_url="http://127.0.0.1:${OMA_MONITOR_PORT}/healthz"
healthy=false
actual_version=""
deadline=$((SECONDS + 30))

while (( SECONDS < deadline )); do
    if actual_version="$(python3 - "$health_url" "$expected_version" <<'PY' 2>/dev/null
import json
import sys
import urllib.request

url, expected = sys.argv[1], sys.argv[2]
with urllib.request.urlopen(url, timeout=2) as resp:
    if resp.status != 200:
        raise SystemExit(1)
    data = json.loads(resp.read().decode("utf-8"))
if data.get("status") != "ok":
    raise SystemExit(1)
version = data.get("version", "")
if expected and version != expected:
    raise SystemExit(1)
print(version)
PY
)"; then
        healthy=true
        break
    fi
    sleep 1
done

# 6. If the health check fails, remove the new container, rename the backup back and start it.
if [[ "$healthy" != true ]]; then
    rollback
    exit 1
fi

# 7. Delete all but the last 3 backup containers.
mapfile -t old_backups < <(
    docker ps -a --filter "name=^/${container}-backup-" --format '{{.Names}}' \
        | sort -r \
        | tail -n +4
)
for old_backup in "${old_backups[@]}"; do
    [[ -n "$old_backup" ]] && docker rm -f "$old_backup" >/dev/null
done

# Start Caddy only if it isn't already running.
caddy_name="${PULSE_CADDY_NAME:-oma-pulse-caddy}"
caddy_running="$(docker inspect --format '{{.State.Running}}' "$caddy_name" 2>/dev/null || true)"
if [[ "$caddy_running" != "true" ]]; then
    if docker container inspect "$caddy_name" >/dev/null 2>&1; then
        docker start "$caddy_name" >/dev/null
    else
        bash "$deploy_dir/caddy.sh" "$env_file"
    fi
fi

# 8. Append one line to ~/omega-pulse/deploys.log with time, version, image digest and who triggered it.
log_dir="$HOME/omega-pulse"
mkdir -p "$log_dir"
triggered_by="${DEPLOY_TRIGGERED_BY:-${GITHUB_ACTOR:-${USER:-unknown}}}"
printf '%s version=%s image=%s digest=%s triggered_by=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "${actual_version:-${expected_version:-unknown}}" \
    "$image" \
    "$image_digest" \
    "$triggered_by" >> "$log_dir/deploys.log"

printf 'Deployed %s (version=%s)\n' "$image" "${actual_version:-${expected_version:-unknown}}"

