#!/bin/zsh

 podman run --rm -it \
  -v "$PWD/apps:/speculos/apps" \
  -p 5001:5000 \
  -p 9999:9999 \
  ghcr.io/ledgerhq/speculos \
  --seed "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --model nanosp \
  --display headless \
  apps/sui.elf
