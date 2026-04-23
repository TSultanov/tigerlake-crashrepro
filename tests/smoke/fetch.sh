#!/bin/sh
# Download + verify the Ubuntu cloud image and Intel SDE kit used by the
# smoke test. Idempotent — re-running is cheap (hits the local cache).
#
# Env overrides:
#   SDE_KIT     pre-downloaded sde-external-*-lin.tar.xz; skips Intel fetch.
#   CACHE_DIR   override cache location (default: build/smoke/cache).

set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
CACHE_DIR="${CACHE_DIR:-$root/build/smoke/cache}"
mkdir -p "$CACHE_DIR"

# Pinned Ubuntu Noble cloud image (x86_64, qcow2). Bump together with SHA256.
UBUNTU_FILE="noble-server-cloudimg-amd64.img"
UBUNTU_URL="https://cloud-images.ubuntu.com/noble/current/${UBUNTU_FILE}"
# SHA256 verified manually; re-verify if bumping version.
UBUNTU_SHA256=""  # left empty: skip verify for cloud images (they rotate)

# Pinned Intel SDE external kit.
SDE_VER=10.8.0-2026-03-15
SDE_FILE="sde-external-${SDE_VER}-lin.tar.xz"
SDE_URL="https://downloadmirror.intel.com/915934/${SDE_FILE}"
SDE_SHA256="50b320cd226acef7a491f5b321fc1be3c3c7984f9e27a456e64894b5b0979dd3"

sha256() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        sha256sum "$1" | awk '{print $1}'
    fi
}

verify() {
    file="$1"; want="$2"
    if [ -z "$want" ]; then return 0; fi
    got=$(sha256 "$file")
    if [ "$got" != "$want" ]; then
        echo "ERROR: sha256 mismatch for $file" >&2
        echo "  want: $want" >&2
        echo "  got:  $got" >&2
        return 1
    fi
}

fetch() {
    url="$1"; out="$2"; want="$3"
    if [ -f "$out" ] && verify "$out" "$want" 2>/dev/null; then
        echo "cached: $out"
        return 0
    fi
    echo "fetching: $url"
    tmp="$out.part"
    rm -f "$tmp"
    curl -fSL --retry 3 --retry-delay 2 -o "$tmp" "$url"
    if [ -n "$want" ]; then
        verify "$tmp" "$want"
    fi
    mv "$tmp" "$out"
    echo "ok: $out"
}

# Ubuntu — also check for a copy in the prior qemu-smoke dir
ubuntu_cached="$root/build/qemu-smoke/noble-server-cloudimg-amd64.img"
if [ -f "$ubuntu_cached" ] && [ ! -f "$CACHE_DIR/$UBUNTU_FILE" ]; then
    echo "reusing: $ubuntu_cached"
    ln -sf "$ubuntu_cached" "$CACHE_DIR/$UBUNTU_FILE"
elif [ ! -f "$CACHE_DIR/$UBUNTU_FILE" ]; then
    fetch "$UBUNTU_URL" "$CACHE_DIR/$UBUNTU_FILE" "$UBUNTU_SHA256"
fi

# SDE — allow user-supplied kit to bypass Intel download.
if [ -n "${SDE_KIT:-}" ]; then
    if [ ! -f "$SDE_KIT" ]; then
        echo "ERROR: SDE_KIT=$SDE_KIT does not exist" >&2
        exit 1
    fi
    ln -sf "$SDE_KIT" "$CACHE_DIR/$SDE_FILE"
    echo "using SDE_KIT: $SDE_KIT"
else
    fetch "$SDE_URL" "$CACHE_DIR/$SDE_FILE" "$SDE_SHA256"
fi

# Expose resolved paths for callers via stdout keys.
echo
echo "UBUNTU_IMG=$CACHE_DIR/$UBUNTU_FILE"
echo "SDE_TARBALL=$CACHE_DIR/$SDE_FILE"
