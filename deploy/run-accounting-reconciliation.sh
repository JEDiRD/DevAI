#!/bin/bash
set -euo pipefail
set -a
source /home/ubuntu/.config/devai/runtime.env
set +a
export PYTHONPATH=/home/ubuntu/devai-platform/controller
exec /home/ubuntu/devai-platform/.venv/bin/python -m devai.reconciliation
