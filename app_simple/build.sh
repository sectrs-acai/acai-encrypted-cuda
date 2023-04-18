#!/usr/bin/env bash

set -euo pipefail
HERE_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

source $HERE_DIR/../../../scripts/env-aarch64.sh
PREFIX=$HERE_DIR/../install

# "${@:2}"
case "$1" in
    clean)
        ;;
    gcc)
        make  clean
        make gcc GDEV_PREFIX=$OUTPUT_LINUX_CCA_GUEST_DIR/staging/usr/local PREFIX=$PREFIX
        make install GDEV_PREFIX=$OUTPUT_LINUX_CCA_GUEST_DIR/staging/usr/local PREFIX=$PREFIX

    ;;
    nvcc)
        make nvcc GDEV_PREFIX=$OUTPUT_LINUX_CCA_GUEST_DIR/staging/usr/local PREFIX=$PREFIX
        ;;
    *)
      echo "unknown"
      exit 1
       ;;
esac
