#!/bin/bash
set -euo pipefail

cd nym
cargo build --release

cd shadow
bash init.sh
bash runshadow.sh
python timestamps.py
