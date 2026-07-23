// SPDX-License-Identifier: MIT
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define __u8 uint8_t
#define __u32 uint32_t
#define __le16 uint16_t
#define __le32 uint32_t
#define __le64 uint64_t
#define u8 uint8_t
#define __packed __attribute__((packed))
#define le16_to_cpu(value) (value)
#define cpu_to_le64(value) (value)
#define round_up(value, alignment) (((value) + (alignment) - 1) / (alignment) * (alignment))
#define BUILD_BUG_ON(condition) _Static_assert(!(condition), "vendor layout assertion")
#define BIT_ULL(nr) (1ULL << (nr))

#include "../vendor/linux/fs/erofs/erofs_fs.h"

#define CHECK_SIZE(type, expected) _Static_assert(sizeof(struct type) == (expected), #type " size")
#define CHECK_OFFSET(type, member, expected) \
	_Static_assert(offsetof(struct type, member) == (expected), #type "." #member " offset")

CHECK_SIZE(erofs_super_block, 144);
CHECK_OFFSET(erofs_super_block, magic, 0);
CHECK_OFFSET(erofs_super_block, blkszbits, 12);
CHECK_OFFSET(erofs_super_block, meta_blkaddr, 40);
CHECK_OFFSET(erofs_super_block, feature_incompat, 80);
CHECK_OFFSET(erofs_super_block, build_time, 108);
CHECK_OFFSET(erofs_super_block, rootnid_8b, 112);
CHECK_OFFSET(erofs_super_block, metabox_nid, 128);

CHECK_SIZE(erofs_inode_compact, 32);
CHECK_OFFSET(erofs_inode_compact, i_format, 0);
CHECK_OFFSET(erofs_inode_compact, i_size, 8);
CHECK_OFFSET(erofs_inode_compact, i_mtime, 12);
CHECK_OFFSET(erofs_inode_compact, i_uid, 24);

CHECK_SIZE(erofs_inode_extended, 64);
CHECK_OFFSET(erofs_inode_extended, i_format, 0);
CHECK_OFFSET(erofs_inode_extended, i_size, 8);
CHECK_OFFSET(erofs_inode_extended, i_mtime, 32);
CHECK_OFFSET(erofs_inode_extended, i_nlink, 44);

CHECK_SIZE(erofs_dirent, 12);
CHECK_OFFSET(erofs_dirent, nid, 0);
CHECK_OFFSET(erofs_dirent, nameoff, 8);
CHECK_OFFSET(erofs_dirent, file_type, 10);
CHECK_OFFSET(erofs_dirent, reserved, 11);

CHECK_SIZE(erofs_deviceslot, 128);
CHECK_OFFSET(erofs_deviceslot, blocks_lo, 64);
CHECK_OFFSET(erofs_deviceslot, uniaddr_hi, 74);
CHECK_SIZE(erofs_xattr_ibody_header, 12);
CHECK_SIZE(erofs_xattr_entry, 4);
CHECK_SIZE(erofs_inode_chunk_info, 4);
CHECK_SIZE(erofs_inode_chunk_index, 8);
CHECK_OFFSET(erofs_inode_chunk_index, device_id, 2);
CHECK_OFFSET(erofs_inode_chunk_index, startblk_lo, 4);
CHECK_SIZE(z_erofs_map_header, 8);
CHECK_OFFSET(z_erofs_map_header, h_advise, 4);
CHECK_SIZE(z_erofs_lcluster_index, 8);
CHECK_OFFSET(z_erofs_lcluster_index, di_clusterofs, 2);
CHECK_SIZE(z_erofs_extent, 32);
CHECK_OFFSET(z_erofs_extent, pstart_hi, 8);
CHECK_OFFSET(z_erofs_extent, lstart_hi, 16);

int main(void)
{
	return 0;
}
