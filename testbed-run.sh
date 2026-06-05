#!/bin/bash
set -euo pipefail

cd nym
NYM_AVERAGE_PACKET_DELAY=50 cargo build --release

cd shadow
#bash init.sh
bash runmany.sh
