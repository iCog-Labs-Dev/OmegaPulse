#!/usr/bin/env bash
# Start the Caddy TLS proxy for one environment: bash deploy/caddy.sh deploy/staging.env
set -euo pipefail
deploy_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
env_file="$(cd -- "$(dirname -- "$1")" && pwd)/$(basename -- "$1")"
name="${PULSE_CADDY_NAME:-oma-pulse-caddy}"
if docker container inspect "$name" >/dev/null 2>&1; then
    printf 'Container %s already exists; remove it to recreate.\n' "$name" >&2
    exit 1
fi
docker run -d --name "$name" --restart unless-stopped --network host \
    --env-file "$env_file" \
    --mount "type=bind,src=$deploy_dir/Caddyfile,dst=/etc/caddy/Caddyfile,readonly" \
    --mount type=volume,src=oma-pulse-caddy-data,dst=/data \
    --mount type=volume,src=oma-pulse-caddy-config,dst=/config \
    caddy:2.10.2
