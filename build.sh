#!/bin/sh
# Cross-compile crashrepro for Linux x86_64 from any host supported by zig cc.
# Produces a static musl binary so the target Linux machine does not need a
# matching glibc.
set -eu

CC="${CC:-zig cc}"
TARGET="${TARGET:-x86_64-linux-musl}"
OUT="${OUT:-crashrepro}"

# Feature flags are explicit rather than relying solely on -march=tigerlake so
# the binary keeps working if we ever target a different AVX-512 SKU.
CFLAGS="-O2 -g -static -pthread
  -march=tigerlake
  -mavx512f -mavx512dq -mavx512cd -mavx512bw -mavx512vl
  -mavx512vbmi -mavx512vbmi2 -mavx512ifma -mavx512vnni
  -mavx512bitalg -mavx512vpopcntdq
  -Wall -Wextra -Wno-unused-parameter -Wno-unused-function
  -D_GNU_SOURCE"

# shellcheck disable=SC2086
exec $CC -target "$TARGET" $CFLAGS src/*.c -o "$OUT"
