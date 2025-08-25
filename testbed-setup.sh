#!/bin/bash
set -euo pipefail

if [ -e "nym" ] ; then
    echo "nym repository already cloned"
    echo "remove before continuing!"
    exit 1
fi

PATCH_BASE="f8317f5a03bd5d7fb5a66f53730b00aeb03484a7"
REPO="https://github.com/nymtech/nym"

git clone --revision=$PATCH_BASE --depth=1 "$REPO"
cd nym
git apply ../testbed.patch
