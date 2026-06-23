#!/bin/bash
set -euo pipefail
for i in {1..5} ; do
    rm -rf "target/criterion/length_$i"
    mkdir -p "target/criterion/length_$i/"
    SPHINX_MAX_PATH_LENGTH=$i cargo bench -- 'sphinx (creation|unwrap|surb)'
    mv "target/criterion/sphinx creation "* "target/criterion/length_$i"
    mv "target/criterion/sphinx unwrap "* "target/criterion/length_$i"
    mv "target/criterion/sphinx surb" "target/criterion/length_$i"
done
