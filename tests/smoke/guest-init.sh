#!/bin/sh
# In-guest smoke runner. Uploaded and executed via SSH from the host.
# Assumes:
#   /tmp/crashrepro     — the binary
#   /tmp/sde.tar.xz     — Intel SDE tarball
#   SMOKE_ITERS env var  — iteration count (default 500)
#
# Exits 0 on pass, non-zero on fail.

set -eu

ITERS="${SMOKE_ITERS:-500}"
WORKDIR=/tmp/smoke-run
LOGDIR="$WORKDIR/logs"
SDE_DIR="$WORKDIR/sde"

mkdir -p "$WORKDIR" "$LOGDIR"
cp /tmp/crashrepro "$WORKDIR/crashrepro"
chmod +x "$WORKDIR/crashrepro"
cd "$WORKDIR"

echo "=== crashrepro smoke test ==="
uname -a
echo "iters=$ITERS"
grep -co 'avx512f' /proc/cpuinfo 2>/dev/null || echo "avx512f not in cpuinfo"

# --- shared crashrepro args (README smoke command, no side-effects) ---
COMMON="--threads=1 --iters=$ITERS --churn=off --dirty-upper=off \
        --gather-scatter-partial-fault=off --tlb-noise=off \
        --smt-antagonist=off --fork-churn=off --interrupts=off \
        --faults=off --quiet"

pass_check() {
    label="$1"; rc="$2"; logdir="$3"
    if [ "$rc" != "0" ]; then
        echo "FAIL[$label]: exit=$rc"
        return 1
    fi
    # crashrepro pre-creates crash.t*.log as empty files; only non-empty
    # ones indicate an actual crash/signal event.
    for f in "$logdir"/crash.t*.log; do
        [ -f "$f" ] || continue
        if [ -s "$f" ]; then
            echo "FAIL[$label]: non-empty crash log: $f"
            ls -la "$logdir"/
            head -20 "$f" 2>/dev/null || true
            return 1
        fi
    done
    return 0
}

# --- native attempt ---
guest_has_avx512() {
    grep -qE '^flags[[:space:]]*:.*[[:space:]]avx512f([[:space:]]|$)' /proc/cpuinfo
}

if guest_has_avx512; then
    echo
    echo "=== native attempt (guest has avx512f) ==="
    native_log="$LOGDIR/native"
    mkdir -p "$native_log"
    # shellcheck disable=SC2086
    echo ">>> ./crashrepro $COMMON --logdir=$native_log"
    set +e
    # shellcheck disable=SC2086
    ./crashrepro $COMMON --logdir="$native_log" 2>&1
    native_rc=$?
    set -e

    if pass_check native "$native_rc" "$native_log"; then
        echo
        echo "PASS (native)"
        exit 0
    fi
    echo "native attempt failed (rc=$native_rc); falling back to SDE"
else
    echo "guest lacks avx512f; skipping native, going straight to SDE"
fi

# --- SDE fallback ---
echo
echo "=== SDE fallback ==="

# Extract SDE
if [ ! -x "$SDE_DIR/sde64" ]; then
    echo "extracting SDE..."
    mkdir -p "$SDE_DIR"
    tar -xJf /tmp/sde.tar.xz -C "$SDE_DIR" --strip-components=1
fi

if [ ! -x "$SDE_DIR/sde64" ]; then
    echo "FAIL: sde64 not found after extraction"
    ls -la "$SDE_DIR/" || true
    exit 2
fi

# Pin's ptrace scope check
if [ -w /proc/sys/kernel/yama/ptrace_scope ]; then
    echo 0 > /proc/sys/kernel/yama/ptrace_scope || true
fi

sde_log="$LOGDIR/sde"
mkdir -p "$sde_log"

# Choose SDE CPU knob — prefer Tiger Lake to match target
sde_knob="-tgl"
if ! "$SDE_DIR/sde64" -help 2>&1 | grep -q -- "$sde_knob"; then
    # fallback to whatever the SDE version supports
    for knob in -rkl -icx -skx; do
        if "$SDE_DIR/sde64" -help 2>&1 | grep -q -- "$knob"; then
            sde_knob="$knob"
            break
        fi
    done
fi
echo "SDE knob: $sde_knob"

# shellcheck disable=SC2086
echo ">>> $SDE_DIR/sde64 $sde_knob -- ./crashrepro $COMMON --logdir=$sde_log"
set +e
# shellcheck disable=SC2086
"$SDE_DIR/sde64" $sde_knob -- ./crashrepro $COMMON --logdir="$sde_log" 2>&1
sde_rc=$?
set -e

if pass_check sde "$sde_rc" "$sde_log"; then
    echo
    echo "PASS (sde)"
    exit 0
fi

echo
echo "FAIL (sde, rc=$sde_rc)"
exit 1
