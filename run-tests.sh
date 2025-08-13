#!/bin/bash
set -e

export RUST_TEST_THREADS=1
cargo test $1 -- --nocapture | tee test_output.txt