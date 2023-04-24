#!/usr/bin/env bash
set -xu

INSTALL_DIR="$(realpath install)"
#INSTALL_DIR=/usr/local

make -C enc_cuda clean
make -C enc_cuda install PREFIX=$INSTALL_DIR NDEBUG=1
make -C app install PREFIX=$INSTALL_DIR NDEBUG=1
