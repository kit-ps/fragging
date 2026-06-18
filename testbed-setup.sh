#!/bin/bash
set -euo pipefail

say() {
    echo -e "\033[33m$1\033[0m"
}

if [ -e "nym" ] ; then
    echo "nym repository already cloned"
    echo "remove before continuing!"
    exit 1
fi

PATCH_BASE="f8317f5a03bd5d7fb5a66f53730b00aeb03484a7"
REPO="https://github.com/nymtech/nym"

say "Attempting shallow clone"
git clone --revision=$PATCH_BASE --depth=1 "$REPO" || (
    say "Shallow clone did not work, falling back to normal clone"
    git clone "$REPO"
    cd nym
    git checkout $PATCH_BASE
)
say "Successfully got nym revision $PATCH_BASE"
cd nym
say "Applying patch"
git apply ../testbed.patch
mkdir shadow/outputs
say "Testbed setup complete, you can now run ./testbed-run.sh"
