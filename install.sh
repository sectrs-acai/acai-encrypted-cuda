#!/usr/bin/env bash
set -xu

INSTALL_DIR="$(realpath install)"

make -C enc_cuda clean
make -C enc_cuda install PREFIX=$INSTALL_DIR
make -C app install PREFIX=$INSTALL_DIR
