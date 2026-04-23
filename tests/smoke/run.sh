#!/bin/sh
# Host driver for the crashrepro smoke test.
#
# Boots Ubuntu Noble under qemu-system-x86_64 (TCG) with cloud-init SSH
# access, uploads the test binary and Intel SDE via SCP, runs the smoke
# script over SSH, and reports PASS/FAIL.
#
# Works on ARM64 macOS hosts that have no native AVX-512. The guest
# attempts native QEMU-TCG execution first; on failure it falls back to
# Intel SDE.
#
# Env:
#   SMOKE_ITERS      crashrepro --iters inside the guest (default 500)
#   SMOKE_TIMEOUT    host-side wall-clock timeout in seconds (default 1800)
#   SMOKE_MEM        QEMU -m value (default 4G)
#   SMOKE_SMP        QEMU -smp value (default 2)
#   SDE_KIT          pre-downloaded sde-external-*-lin.tar.xz
#   SMOKE_SSH_PORT   host port forwarded to guest :22 (default 10222)
#   KEEP_VM=1        leave VM running after test for debugging

set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
build_dir="$root/build/smoke"
cache="$build_dir/cache"
mkdir -p "$build_dir" "$cache"

MEM="${SMOKE_MEM:-4G}"
SMP="${SMOKE_SMP:-2}"
ITERS="${SMOKE_ITERS:-500}"
TIMEOUT="${SMOKE_TIMEOUT:-1800}"
SSH_PORT="${SMOKE_SSH_PORT:-10222}"

# ----- deps -----
need() {
    command -v "$1" >/dev/null 2>&1 || { echo "ERROR: need '$1' on PATH" >&2; exit 1; }
}
need qemu-system-x86_64
need qemu-img
need curl
need tar
need xz
need ssh
need scp

# ----- build the binary if needed -----
if [ ! -x "$root/crashrepro" ] || [ -n "$(find "$root/src" -newer "$root/crashrepro" -print -quit 2>/dev/null)" ]; then
    echo "==> building crashrepro"
    (cd "$root" && ./build.sh)
fi
[ -x "$root/crashrepro" ] || { echo "ERROR: crashrepro not built" >&2; exit 1; }

# ----- fetch ubuntu + sde -----
echo "==> fetch"
fetch_out=$("$here/fetch.sh")
echo "$fetch_out"
UBUNTU_IMG=$(echo "$fetch_out" | sed -n 's/^UBUNTU_IMG=//p')
SDE_TARBALL=$(echo "$fetch_out" | sed -n 's/^SDE_TARBALL=//p')
[ -f "$UBUNTU_IMG" ] || { echo "ERROR: no ubuntu image"; exit 1; }
[ -f "$SDE_TARBALL" ] || { echo "ERROR: no sde tarball"; exit 1; }

# ----- SSH key pair (one-time) -----
ssh_key="$build_dir/smoke_ed25519"
if [ ! -f "$ssh_key" ]; then
    echo "==> generating SSH key pair"
    ssh-keygen -t ed25519 -f "$ssh_key" -N "" -q
fi
ssh_pub=$(cat "$ssh_key.pub")

# ----- cloud-init seed ISO -----
# Minimal: create user with SSH key, no password, enable SSH.
seed_dir="$build_dir/seed"
seed_iso="$build_dir/seed.iso"
mkdir -p "$seed_dir"

cat >"$seed_dir/user-data" <<EOF
#cloud-config
users:
  - name: smoke
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $ssh_pub
ssh_pwauth: false
runcmd:
  - systemctl disable --now unattended-upgrades.service 2>/dev/null || true
  - systemctl disable --now apt-daily.timer 2>/dev/null || true
  - systemctl disable --now apt-daily-upgrade.timer 2>/dev/null || true
EOF

cat >"$seed_dir/meta-data" <<EOF
instance-id: crashrepro-smoke
local-hostname: crashrepro-smoke
EOF

cat >"$seed_dir/vendor-data" <<'EOF'
EOF

# Build NoCloud seed ISO with hdiutil on macOS.
# cloud-init expects either a CDROM labeled "cidata" or a specific path.
rm -f "$seed_iso"
hdiutil makehybrid -iso -joliet -default-volume-name cidata \
    -o "$seed_iso" "$seed_dir" 2>/dev/null

# ----- guest disk (ephemeral overlay) -----
guest_img="$build_dir/guest.qcow2"
echo "==> creating ephemeral guest disk overlay"
rm -f "$guest_img"
qemu-img create -f qcow2 -b "$UBUNTU_IMG" -F qcow2 "$guest_img" 10G >/dev/null

# ----- launch QEMU -----
echo "==> boot qemu"
serial_log="$build_dir/serial.log"
rm -f "$serial_log"

qemu-system-x86_64 \
    -name crashrepro-smoke \
    -machine q35,accel=tcg \
    -cpu max \
    -smp "$SMP" \
    -m "$MEM" \
    -display none \
    -monitor none \
    -serial "file:$serial_log" \
    -nic "user,model=virtio-net-pci,hostfwd=tcp::${SSH_PORT}-:22" \
    -device virtio-rng-pci \
    -drive "if=virtio,format=qcow2,file=$guest_img" \
    -drive "if=virtio,media=cdrom,readonly=on,format=raw,file=$seed_iso" \
    -no-reboot \
    &
qemu_pid=$!
echo "qemu pid=$qemu_pid"

cleanup() {
    if kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
}
trap cleanup EXIT

# Watchdog
( sleep "$TIMEOUT"
  echo "!! smoke timeout after ${TIMEOUT}s" >&2
  kill "$qemu_pid" 2>/dev/null || true
) &
watchdog_pid=$!

# ----- common SSH options -----
SSH_COMMON="-o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -o ConnectTimeout=5 \
    -o ServerAliveInterval=10 \
    -i $ssh_key"

do_ssh() {
    # shellcheck disable=SC2086
    ssh $SSH_COMMON -p "$SSH_PORT" smoke@127.0.0.1 "$@"
}

do_scp() {
    # scp uses -P (uppercase) for port
    # shellcheck disable=SC2086
    scp $SSH_COMMON -P "$SSH_PORT" "$@"
}

# ----- wait for SSH -----
echo "==> waiting for SSH (this takes 1-3 min under TCG)..."
attempts=0
max_attempts=120  # 120 * 5s = 10 min
while ! do_ssh true 2>/dev/null; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge "$max_attempts" ]; then
        echo "ERROR: SSH not ready after $((max_attempts * 5))s"
        echo "==> serial log tail:"
        tail -40 "$serial_log" 2>/dev/null || true
        exit 2
    fi
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        echo "ERROR: QEMU exited before SSH became available"
        echo "==> serial log tail:"
        tail -40 "$serial_log" 2>/dev/null || true
        exit 2
    fi
    sleep 5
done
echo "==> SSH ready (after ~$((attempts * 5))s)"

# ----- upload payload -----
echo "==> uploading crashrepro binary"
do_scp "$root/crashrepro" smoke@127.0.0.1:/tmp/crashrepro

echo "==> uploading SDE tarball"
do_scp "$SDE_TARBALL" smoke@127.0.0.1:/tmp/sde.tar.xz

echo "==> uploading guest runner"
do_scp "$here/guest-init.sh" smoke@127.0.0.1:/tmp/guest-init.sh

# ----- run the smoke test over SSH -----
echo "==> running smoke test in guest"
rc=0
do_ssh "sudo chmod +x /tmp/crashrepro /tmp/guest-init.sh && \
    sudo SMOKE_ITERS=$ITERS /tmp/guest-init.sh" || rc=$?

echo "==> guest exited with code $rc"

# ----- result -----
echo "==> serial log tail:"
tail -30 "$serial_log" 2>/dev/null || true

if [ -n "${KEEP_VM:-}" ]; then
    echo "KEEP_VM set — VM still running. SSH: ssh $SSH_COMMON -p $SSH_PORT smoke@127.0.0.1"
    wait "$qemu_pid" || true
fi

if [ "$rc" -eq 0 ]; then
    echo "SMOKE_RESULT=PASS"
    exit 0
else
    echo "SMOKE_RESULT=FAIL (exit=$rc)"
    exit 1
fi
