#!/usr/bin/env bash

set -euo pipefail
HERE_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $HERE_DIR/../../../scripts/env-aarch64.sh

TARGET_SRC=$HERE_DIR
INSTALL=$HERE_DIR/../install

# "${@:2}"
case "$1" in
    clean)
        ;;
    gcc)
        make -C $TARGET_SRC clean
        make -C $TARGET_SRC gcc PREFIX=$INSTALL GDEV_PREFIX=$OUTPUT_LINUX_CCA_GUEST_DIR/staging/usr/local
        make -C $TARGET_SRC install PREFIX=$INSTALL
    ;;
    nvcc)
        make -C $TARGET_SRC nvcc PREFIX=$INSTALL GDEV_PREFIX=$OUTPUT_LINUX_CCA_GUEST_DIR/staging/usr/local
        make -C $TARGET_SRC install-cubins PREFIX=$INSTALL
        ;;
    *)
      echo "unknown"
      exit 1
       ;;
esac
