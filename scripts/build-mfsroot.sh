#!/bin/sh


SCRIPT_DIR=$(realpath "$(dirname "$0")")


set -eu

usage() {
    cat <<'EOF'
Usage: build-mfsroot.sh --output <path> --kunci <path> --release <ver> [options]

Options:
  --output <path>          Output mfsroot image path (required)
  --kunci <path>           Path to kunci-client binary (required)
  --release <ver>          FreeBSD release version (e.g., 14.2-RELEASE)
  --arch <arch>            FreeBSD target arch for mfsbsd build (default: uname -m)
  --shell <path>           Static shell to install as /bin/sh
  --root <path>            Staging root directory (default: temp dir)
  --init <path>            Init script path (default: built-in template)
  --keep-list <path>       Keep list for reverse pruning (one entry per line)
  --pin-config <path>      Pin config JSON to copy into /etc/kunci/pin.json
  --datasets <list>        Space-separated datasets for KUNCI_DATASETS
  --root-dataset <name>    Root dataset for KUNCI_ROOT_DATASET
  --pin <name>             Pin name for KUNCI_PIN
  --dhcp <yes|no>          Enable DHCP in init (default: yes)
  --netif <ifname>         Interface name for KUNCI_NETIF
  --kunci-opts <string>    Extra options passed to kunci
  --netcheck <yes|no>      Enable one-shot net check (default: no)
  --size <mb>              Size for mfsroot image (default: auto)
  --keep-root              Do not delete temporary staging root
EOF
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing command: $1" >&2
        exit 1
    fi
}

copy_file() {
    src="$1"
    dst="$2"
    mkdir -p "$(dirname "$dst")"
    install -m 444 "$src" "$dst"
}

keep_add_path() {
    path="$1"
    if [ -e "$path" ]; then
        printf "%s\n" "$path" >>"$KEEP_TMP"
        if command -v realpath >/dev/null 2>&1; then
            real="$(realpath "$path" 2>/dev/null || true)"
            if [ -n "$real" ]; then
                printf "%s\n" "$real" >>"$KEEP_TMP"
            fi
        fi
    fi
}

resolve_keep_bin() {
    name="$1"
    for dir in /bin /sbin /usr/bin /usr/sbin /rescue; do
        if [ -x "$ROOT$dir/$name" ]; then
            echo "$ROOT$dir/$name"
            return 0
        fi
    done
    return 1
}

apply_keep_list() {
    KEEP_TMP="$(mktemp /tmp/kunci-keep.XXXXXX)"
    keep_add_path "$ROOT/sbin/init"
    keep_add_path "$ROOT/bin/kunci-client"
    keep_add_path "$ROOT/bin/sh"
    keep_add_path "$ROOT/libexec/ld-elf.so.1"

    if [ -n "$KEEP_LIST" ] && [ -f "$KEEP_LIST" ]; then
        while IFS= read -r entry; do
            case "$entry" in
                ""|\#*) continue ;;
            esac
            if [ "${entry#/}" != "$entry" ]; then
                keep_add_path "$ROOT$entry"
            else
                if path="$(resolve_keep_bin "$entry")"; then
                    keep_add_path "$path"
                else
                    echo "WARN: keep entry not found: $entry" >&2
                fi
            fi
        done <"$KEEP_LIST"
    fi

    sort -u "$KEEP_TMP" >"${KEEP_TMP}.sorted"
    mv "${KEEP_TMP}.sorted" "$KEEP_TMP"

    while IFS= read -r bin; do
        if [ -x "$bin" ] && [ ! -d "$bin" ]; then
            ldd "$bin" 2>/dev/null | awk '{for (i=1; i<=NF; i++) if (substr($i,1,1)=="/") print $i}' \
                | sort -u | while read -r lib; do
                    keep_add_path "$ROOT$lib"
                done
        fi
    done <"$KEEP_TMP"

    sort -u "$KEEP_TMP" >"${KEEP_TMP}.sorted"
    mv "${KEEP_TMP}.sorted" "$KEEP_TMP"

    for dir in /bin /sbin /usr/bin /usr/sbin /rescue /lib /usr/lib /libexec; do
        if [ -d "$ROOT$dir" ]; then
            find "$ROOT$dir" \( -type f -o -type l \) | while read -r path; do
                if ! grep -qx "$path" "$KEEP_TMP"; then
                    if command -v chflags >/dev/null 2>&1; then
                        chflags -h noschg "$path" 2>/dev/null || true
                        chflags -h nouchg "$path" 2>/dev/null || true
                        chflags -h nosappnd "$path" 2>/dev/null || true
                        chflags -h nouappnd "$path" 2>/dev/null || true
                    fi
                    rm -f "$path"
                fi
            done
        fi
    done

    keep_boot="no"
    if grep -q "$ROOT/boot" "$KEEP_TMP"; then
        keep_boot="yes"
    fi
    for dir in /boot /home /root /usr/include /usr/libdata /usr/share /usr/src /usr/tests /var/cache /var/db /var/log /var/tmp; do
        if [ "$dir" = "/boot" ] && [ "$keep_boot" = "yes" ]; then
            continue
        fi
        if [ -d "$ROOT$dir" ]; then
            rm -rf "$ROOT$dir"
        fi
    done
}

write_default_init() {
    if [ -e "$ROOT/sbin/init" ]; then
        if command -v chflags >/dev/null 2>&1; then
            chflags -f noschg "$ROOT/sbin/init" 2>/dev/null || true
        fi
        rm -f "$ROOT/sbin/init" 2>/dev/null || true
    fi
    cp "$SCRIPT_DIR/assets/init" "$ROOT/sbin/init"
    chmod 555 "$ROOT/sbin/init"
}

OUTPUT=""
KUNCI_BIN=""
RELEASE=""
ARCH=""
ROOT=""
INIT_SRC=""
SHELL_BIN=""
PRUNE_LIST=""
KEEP_LIST=""
PIN_CONFIG=""
DATASETS=""
ROOT_DATASET=""
PIN_NAME=""
DHCP="yes"
NETIF=""
KUNCI_OPTS=""
NETCHECK=""
KEEP_ROOT="no"
IMAGE_SIZE_MB=""

while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        --kunci)
            KUNCI_BIN="$2"
            shift 2
            ;;
        --release)
            RELEASE="$2"
            shift 2
            ;;
        --arch)
            ARCH="$2"
            shift 2
            ;;
        --root)
            ROOT="$2"
            shift 2
            ;;
        --shell)
            SHELL_BIN="$2"
            shift 2
            ;;
        --init)
            INIT_SRC="$2"
            shift 2
            ;;
        --keep-list)
            KEEP_LIST="$2"
            shift 2
            ;;
        --pin-config)
            PIN_CONFIG="$2"
            shift 2
            ;;
        --datasets)
            DATASETS="$2"
            shift 2
            ;;
        --root-dataset)
            ROOT_DATASET="$2"
            shift 2
            ;;
        --pin)
            PIN_NAME="$2"
            shift 2
            ;;
        --dhcp)
            DHCP="$2"
            shift 2
            ;;
        --netif)
            NETIF="$2"
            shift 2
            ;;
        --kunci-opts)
            KUNCI_OPTS="$2"
            shift 2
            ;;
        --netcheck)
            NETCHECK="$2"
            shift 2
            ;;
        --size)
            IMAGE_SIZE_MB="$2"
            shift 2
            ;;
        --keep-root)
            KEEP_ROOT="yes"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [ -z "$OUTPUT" ] || [ -z "$KUNCI_BIN" ] || [ -z "$RELEASE" ]; then
    echo "ERROR: --output, --kunci, and --release are required" >&2
    usage
    exit 1
fi

require_cmd fetch
require_cmd gzip
require_cmd ldd
require_cmd install
require_cmd ifconfig
require_cmd dhclient
require_cmd zpool
require_cmd zfs
require_cmd tar
require_cmd makefs

if [ -z "$ROOT" ]; then
    ROOT="$(mktemp -d /tmp/kunci-mfsroot.XXXXXX)"
fi

if [ -z "$ARCH" ]; then
    ARCH="$(uname -m)"
fi

DISTDIR="$(mktemp -d /tmp/kunci-dist.XXXXXX)"
BASE_URL="https://download.freebsd.org/ftp/releases/${ARCH}/${RELEASE}"
fetch -o "$DISTDIR/base.txz" "${BASE_URL}/base.txz"
fetch -o "$DISTDIR/kernel.txz" "${BASE_URL}/kernel.txz"

if [ -z "$KEEP_LIST" ]; then
    KEEP_LIST="${SCRIPT_DIR}/assets/keep.list"
fi

compute_image_size_kb() {
    base_kb="$(du -sk "$ROOT" | awk '{print $1}')"
    if [ -n "$IMAGE_SIZE_MB" ]; then
        echo $((IMAGE_SIZE_MB * 1024))
    else
        echo $((base_kb + base_kb / 5 + 16384))
    fi
}

align_size_kb() {
    size_kb="$1"
    bsize_kb=32
    aligned_kb=$(( (size_kb + bsize_kb - 1) / bsize_kb * bsize_kb ))
    echo $((aligned_kb + bsize_kb))
}

build_minimal_root() {
    tar -xpf "$DISTDIR/base.txz" -C "$ROOT"
    tar -xpf "$DISTDIR/kernel.txz" -C "$ROOT" \
        boot/kernel/kernel \
        boot/kernel/linker.hints \
        boot/kernel/zfs.ko \
        boot/kernel/opensolaris.ko \
        boot/kernel/xdr.ko \
        boot/kernel/zlib.ko \
        boot/kernel/crypto.ko \
        boot/kernel/aesni.ko \
        boot/kernel/acl_nfs4.ko
}

OUTPUT_TMP="${OUTPUT}.tmp"
build_minimal_root

mkdir -p "$ROOT"/etc/kunci

install -m 555 "$KUNCI_BIN" "$ROOT/bin/kunci-client"
KUNCI_RUNTIME_LIBS="/libexec/ld-elf.so.1 /lib/libthr.so.3 /lib/libgcc_s.so.1 /lib/libc.so.7 /lib/libm.so.5 /lib/libsys.so.7"
for lib in ${KUNCI_RUNTIME_LIBS}; do
    dest="$ROOT$lib"
    mkdir -p "$(dirname "$dest")"
    install -m 755 "$lib" "$dest"
done

if [ ! -x "$ROOT/bin/sh" ]; then
    if [ -z "$SHELL_BIN" ]; then
        SHELL_BIN="/usr/local/bin/ksh"
    fi
    if [ -x "$SHELL_BIN" ]; then
        install -m 555 "$SHELL_BIN" "$ROOT/bin/sh"
    elif [ -x "$ROOT/rescue/sh" ]; then
        mkdir -p "$ROOT/bin"
        ln -sf /rescue/sh "$ROOT/bin/sh"
    else
        echo "ERROR: /bin/sh missing in mfsroot staging root and no shell available at $SHELL_BIN" >&2
        exit 1
    fi
fi

if [ -n "$INIT_SRC" ]; then
    install -m 555 "$INIT_SRC" "$ROOT/sbin/init"
else
    write_default_init
fi

build_id="$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null || echo unknown)"
{
    echo "KUNCI_BUILD_ID=\"${build_id}\""
    echo "KUNCI_DATASETS=\"${DATASETS}\""
    echo "KUNCI_ROOT_DATASET=\"${ROOT_DATASET}\""
    echo "KUNCI_PIN=\"${PIN_NAME}\""
    echo "KUNCI_PIN_CONFIG=\"${PIN_CONFIG:+/etc/kunci/pin.json}\""
    echo "KUNCI_DHCP=\"${DHCP}\""
    echo "KUNCI_NETIF=\"${NETIF}\""
    echo "KUNCI_KUNCI_OPTS=\"${KUNCI_OPTS}\""
    echo "KUNCI_NETCHECK=\"${NETCHECK}\""
} >"$ROOT/etc/kunci/boot.conf"

if [ -n "$PIN_CONFIG" ]; then
    copy_file "$PIN_CONFIG" "$ROOT/etc/kunci/pin.json"
fi

if [ -n "$KEEP_LIST" ]; then
    apply_keep_list
fi

size_kb="$(compute_image_size_kb)"
size_kb="$(align_size_kb "$size_kb")"
makefs -t ffs -o version=2 -s "${size_kb}k" "$OUTPUT_TMP" "$ROOT"
mv "$OUTPUT_TMP" "$OUTPUT"

if [ "$KEEP_ROOT" != "yes" ]; then
    chflags -R noschg,nouchg,nosappnd,nouappnd "$DISTDIR" 2>&1 >/dev/null || true
    chflags -R noschg,nouchg,nosappnd,nouappnd "$ROOT" 2>&1 >/dev/null || true
    chmod -R u+w "$ROOT" 2>/dev/null || true
    rm -rf "$ROOT" "$DISTDIR" || true
else
    echo "mfsroot staging root at $ROOT"
    echo "distdir preserved at $DISTDIR"
fi
