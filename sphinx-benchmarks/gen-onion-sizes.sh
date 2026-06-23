#!/bin/bash
set -euo pipefail
echo "path_length,payload_size,onion_size" >sphinx_onion_sizes.csv
for i in {1..5} ; do
    SPHINX_MAX_PATH_LENGTH=$i cargo run --release --bin=onion_size >>sphinx_onion_sizes.csv
done
