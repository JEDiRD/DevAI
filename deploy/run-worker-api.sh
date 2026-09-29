#!/usr/bin/env bash
set -euo pipefail

cd /home/ubuntu/devai-platform
set -a
source /home/ubuntu/.config/devai/runtime.env
set +a

bind_ip=$(tailscale ip -4)
if [ -z "$bind_ip" ]; then
    echo "Tailscale IPv4 address unavailable" >&2
    exit 1
fi

exec .venv/bin/uvicorn devai.worker_api:app \
    --app-dir controller \
    --host "$bind_ip" \
    --port 8765 \
    --no-access-log
