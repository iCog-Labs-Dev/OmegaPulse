#!/usr/bin/env bash
set -euo pipefail
monitor_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
events_dir="${OMA_MONITOR_EVENTS_DIR:-$monitor_dir/.local/falco-events}"
container="${OMA_FALCO_CONTAINER:-oma-falco-live}"
writer_uid="${OMA_MONITOR_WRITER_UID:-$(id -u)}"
writer_gid="${OMA_MONITOR_WRITER_GID:-$(id -g)}"
if [[ ! "$writer_uid" =~ ^[1-9][0-9]*$ || ! "$writer_gid" =~ ^[1-9][0-9]*$ ]]; then
    printf 'Set OMA_MONITOR_WRITER_UID/GID to the non-root monitor account IDs before launching Falco.\n' >&2
    exit 1
fi
export OMA_MONITOR_CONTAINER="${OMA_MONITOR_CONTAINER:-omega}"
if docker container inspect "$container" >/dev/null 2>&1; then
    printf 'Container %s already exists; inspect or resume it.\n' "$container" >&2
    exit 1
fi
umask 077
mkdir -p "$events_dir"
events_dir="$(cd -- "$events_dir" && pwd)"
if [[ "$(stat -c '%u:%g' "$events_dir")" != "$writer_uid:$writer_gid" ]]; then
    printf 'Events directory must be owned by writer UID:GID %s:%s; prepare it before launch.\n' "$writer_uid" "$writer_gid" >&2
    exit 1
fi
PYTHONPATH="$monitor_dir/.." python3 -m monitor.render_rules "$monitor_dir/falco/oma_rules.yaml" "$events_dir/oma_rules.rendered.yaml"
docker build -t oma-falco:local -f "$monitor_dir/falco/Dockerfile" "$monitor_dir"
docker run -d --name "$container" --label oma.monitor.component=falco --privileged \
    -e OMA_MONITOR_WRITER_UID="$writer_uid" -e OMA_MONITOR_WRITER_GID="$writer_gid" \
    -e OMA_MONITOR_LOG_MAX_BYTES="${OMA_MONITOR_LOG_MAX_BYTES:-20480}" \
    -e OMA_MONITOR_LOG_INTERVAL_SECONDS="${OMA_MONITOR_LOG_INTERVAL_SECONDS:-3600}" \
    -e OMA_MONITOR_LOG_KEEP="${OMA_MONITOR_LOG_KEEP:-100}" \
    --mount type=bind,src=/sys/kernel/tracing,dst=/sys/kernel/tracing,readonly \
    --mount type=bind,src=/var/run/docker.sock,dst=/host/var/run/docker.sock \
    --mount type=bind,src=/proc,dst=/host/proc,readonly \
    --mount type=bind,src=/etc,dst=/host/etc,readonly \
    --mount "type=bind,src=$events_dir/oma_rules.rendered.yaml,dst=/rules/oma_rules.yaml,readonly" \
    --mount "type=bind,src=$events_dir,dst=/events" \
    oma-falco:local falco -U -r /rules/oma_rules.yaml \
    -o engine.kind=modern_ebpf -o json_output=true -o buffered_outputs=false \
    -o stdout_output.enabled=false -o file_output.enabled=false \
    -o program_output.enabled=true -o program_output.keep_alive=true \
    -o 'program_output.program=python3 -u /writer/event_writer.py'
