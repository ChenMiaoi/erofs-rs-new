#!/usr/bin/env bash
set -euo pipefail

linux_dir="${1:-vendor/linux}"
build_dir="${2:-$linux_dir}"
config_tool="$linux_dir/scripts/config"
config_file="$build_dir/.config"

if [[ ! -d "$linux_dir" ]]; then
	echo "Linux tree not found: $linux_dir" >&2
	exit 1
fi

mkdir -p "$build_dir"
make -C "$linux_dir" O="$build_dir" ARCH=x86_64 scripts/config >/dev/null

enable_builtin=(
	EROFS_FS
	EROFS_FS_DEBUG
	EROFS_FS_XATTR
	EROFS_FS_POSIX_ACL
	EROFS_FS_SECURITY
	EROFS_FS_BACKED_BY_FILE
	EROFS_FS_ZIP
	EROFS_FS_ZIP_LZMA
	EROFS_FS_ZIP_DEFLATE
	EROFS_FS_ZIP_ZSTD
	EROFS_FS_ZIP_ACCEL
	EROFS_FS_ONDEMAND
	EROFS_FS_PCPU_KTHREAD
	EROFS_FS_PCPU_KTHREAD_HIPRI
	EROFS_FS_PAGE_CACHE_SHARE
	DEVTMPFS
	DEVTMPFS_MOUNT
	BLK_DEV_INITRD
	VIRTIO
	VIRTIO_PCI
	VIRTIO_BLK
	KASAN
	KASAN_INLINE
	KCOV
	KCOV_INSTRUMENT_ALL
	KCOV_ENABLE_COMPARISONS
	DEBUG_FS
	SLUB_DEBUG
	SLUB_DEBUG_ON
	DEBUG_KERNEL
)

for opt in "${enable_builtin[@]}"; do
	"$config_tool" --file "$config_file" --enable "$opt"
done

make -C "$linux_dir" O="$build_dir" ARCH=x86_64 olddefconfig >/dev/null

echo "Enabled EROFS kernel options:"
grep '^CONFIG_EROFS' "$config_file" | sort
