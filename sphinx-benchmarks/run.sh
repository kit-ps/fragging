#!/bin/bash
set -euo pipefail
echo "path_length,payload_size,onion_size" >sphinx_onion_sizes.csv
for i in {1..5} ; do
    rm -rf "target/criterion/length_$i"
    mkdir -p "target/criterion/length_$i/"
    SPHINX_MAX_PATH_LENGTH=$i cargo bench -- 'sphinx (creation|unwrap)'
    mv "target/criterion/sphinx creation" "target/criterion/length_$i"
    mv "target/criterion/sphinx unwrap" "target/criterion/length_$i"
    SPHINX_MAX_PATH_LENGTH=$i cargo run --release --bin=onion_size >>sphinx_onion_sizes.csv
done
