#!/bin/bash
set -euo pipefail

# Optionally: If cpupower is available, change the scaling governor
cpupower frequency-set -g performance || true

# If taskset is available, use it
if taskset --help >/dev/null ; then
    TASKSET="taskset -c 0"
else
    TASKSET=""
fi

(
    cd scylla
    # Approximately 30 minutes
    time $TASKSET cargo bench
    cargo run --release --example=onion_sizes >onion_sizes.csv
)

(
    cd sphinx-benchmarks
    # Approximately 15 minutes
    time $TASKSET ./run.sh
    ./gen-onion-sizes.sh
)

[ -e nym/ ] || ./testbed-setup.sh
time ./testbed-run.sh

(
    cd latency-sim
    # Approximately 4 hours
    time cargo run --release >results.csv
)
