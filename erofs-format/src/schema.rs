//! Pinned EROFS ABI schema metadata.

use crate::Span;

/// Linux commit from which this schema was transcribed.
pub const LINUX_COMMIT: &str = "980ab36ae5972c83f683b939e50c469c4947229e";
/// Stable schema API identifier.
pub const SCHEMA_API: &str = "erofs-abi-schema/v1";
/// Authoritative header within the pinned Linux tree.
pub const SOURCE_HEADER: &str = "fs/erofs/erofs_fs.h";
/// SHA-256 of the canonical schema identity tuple (`api`, commit, header).
pub const SCHEMA_DIGEST: &str =
    "sha256:9ac9ea849d004293196a0e5ddd46b4defe49251207d991ff7312bbf13ae10efa";

/// Identity of the compiled ABI schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaIdentity {
    /// Stable schema API identifier.
    pub api: &'static str,
    /// Pinned Linux source commit.
    pub linux_commit: &'static str,
    /// Authoritative source header.
    pub source_header: &'static str,
    /// Digest of the canonical schema identity tuple.
    pub digest: &'static str,
}

/// Compiled schema identity.
pub const SCHEMA_IDENTITY: SchemaIdentity = SchemaIdentity {
    api: SCHEMA_API,
    linux_commit: LINUX_COMMIT,
    source_header: SOURCE_HEADER,
    digest: SCHEMA_DIGEST,
};

/// On-disk structure containing a field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StructureId {
    /// `struct erofs_super_block`.
    Superblock,
    /// `struct erofs_inode_compact`.
    CompactInode,
    /// `struct erofs_inode_extended`.
    ExtendedInode,
    /// `struct erofs_dirent`.
    Dirent,
    /// Raw superblock extension slot.
    SuperblockExtension,
    /// `struct erofs_deviceslot`.
    DeviceSlot,
    /// `struct erofs_inode_chunk_index` or a 4-byte block entry.
    ChunkEntry,
    /// `struct erofs_xattr_ibody_header`.
    XattrHeader,
    /// Shared xattr ID in an inline xattr header.
    SharedXattrId,
    /// `struct erofs_xattr_entry` and its bounded payload.
    XattrEntry,
    /// Generic long-prefix metadata record.
    XattrLongPrefix,
    /// Generic compression configuration metadata record.
    CompressionConfig,
    /// `struct z_erofs_map_header`.
    CompressionMap,
    /// `struct z_erofs_lcluster_index`.
    CompressionIndex,
    /// One compact lcluster index pack.
    CompressionCompactPack,
    /// One variable-width `struct z_erofs_extent` record.
    CompressionExtent,
}

/// Scalar or byte-array encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Encoding {
    /// Unsigned 8-bit integer.
    U8,
    /// Little-endian unsigned 16-bit integer.
    LeU16,
    /// Little-endian unsigned 32-bit integer.
    LeU32,
    /// Little-endian unsigned 64-bit integer.
    LeU64,
    /// Uninterpreted fixed-width bytes.
    Bytes,
}

/// Predicate controlling whether a semantic view is active.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Predicate {
    /// Field is always present once its containing structure is present.
    Always,
    /// View is active when `EROFS_FEATURE_INCOMPAT_48BIT` is clear.
    Without48Bit,
    /// View is active when `EROFS_FEATURE_INCOMPAT_48BIT` is set.
    With48Bit,
    /// View is active when `EROFS_FEATURE_INCOMPAT_COMPR_CFGS` is clear.
    WithoutCompressionConfig,
    /// View is active when `EROFS_FEATURE_INCOMPAT_COMPR_CFGS` is set.
    WithCompressionConfig,
    /// Field requires a superblock region of at least 144 bytes.
    Superblock144,
    /// Field is present when `EROFS_FEATURE_INCOMPAT_METABOX` is set.
    WithMetabox,
    /// Field is present when `EROFS_FEATURE_INCOMPAT_XATTR_PREFIXES` is set.
    WithXattrPrefixes,
    /// Field is present when `EROFS_FEATURE_INCOMPAT_DEVICE_TABLE` is set.
    WithDeviceTable,
    /// Field length and, for payloads, offset are resolved from the object.
    Dynamic,
}

/// Static definition of one stable schema field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldDef {
    /// Stable semantic field ID.
    pub id: &'static str,
    /// Containing structure.
    pub structure: StructureId,
    /// Byte range relative to the structure start.
    pub storage: Span,
    /// On-disk encoding.
    pub encoding: Encoding,
    /// Field presence predicate.
    pub presence: Predicate,
    /// C member path in the pinned header.
    pub member: &'static str,
}

macro_rules! field {
    ($id:literal, $structure:ident, $offset:literal, $len:literal, $encoding:ident, $presence:ident, $member:literal) => {
        FieldDef {
            id: $id,
            structure: StructureId::$structure,
            storage: Span {
                offset: $offset,
                len: $len,
            },
            encoding: Encoding::$encoding,
            presence: Predicate::$presence,
            member: $member,
        }
    };
}

/// All fields supported by the M5 locator.
pub static FIELDS: &[FieldDef] = &[
    field!(
        "erofs.superblock.magic",
        Superblock,
        0,
        4,
        LeU32,
        Always,
        "erofs_super_block.magic"
    ),
    field!(
        "erofs.superblock.checksum",
        Superblock,
        4,
        4,
        LeU32,
        Always,
        "erofs_super_block.checksum"
    ),
    field!(
        "erofs.superblock.feature_compat",
        Superblock,
        8,
        4,
        LeU32,
        Always,
        "erofs_super_block.feature_compat"
    ),
    field!(
        "erofs.superblock.blkszbits",
        Superblock,
        12,
        1,
        U8,
        Always,
        "erofs_super_block.blkszbits"
    ),
    field!(
        "erofs.superblock.sb_extslots",
        Superblock,
        13,
        1,
        U8,
        Always,
        "erofs_super_block.sb_extslots"
    ),
    field!(
        "erofs.superblock.rootnid_2b",
        Superblock,
        14,
        2,
        LeU16,
        Without48Bit,
        "erofs_super_block.rb.rootnid_2b"
    ),
    field!(
        "erofs.superblock.blocks_hi",
        Superblock,
        14,
        2,
        LeU16,
        With48Bit,
        "erofs_super_block.rb.blocks_hi"
    ),
    field!(
        "erofs.superblock.inos",
        Superblock,
        16,
        8,
        LeU64,
        Always,
        "erofs_super_block.inos"
    ),
    field!(
        "erofs.superblock.epoch",
        Superblock,
        24,
        8,
        LeU64,
        Always,
        "erofs_super_block.epoch"
    ),
    field!(
        "erofs.superblock.fixed_nsec",
        Superblock,
        32,
        4,
        LeU32,
        Always,
        "erofs_super_block.fixed_nsec"
    ),
    field!(
        "erofs.superblock.blocks_lo",
        Superblock,
        36,
        4,
        LeU32,
        Always,
        "erofs_super_block.blocks_lo"
    ),
    field!(
        "erofs.superblock.meta_blkaddr",
        Superblock,
        40,
        4,
        LeU32,
        Always,
        "erofs_super_block.meta_blkaddr"
    ),
    field!(
        "erofs.superblock.xattr_blkaddr",
        Superblock,
        44,
        4,
        LeU32,
        Always,
        "erofs_super_block.xattr_blkaddr"
    ),
    field!(
        "erofs.superblock.uuid",
        Superblock,
        48,
        16,
        Bytes,
        Always,
        "erofs_super_block.uuid"
    ),
    field!(
        "erofs.superblock.volume_name",
        Superblock,
        64,
        16,
        Bytes,
        Always,
        "erofs_super_block.volume_name"
    ),
    field!(
        "erofs.superblock.feature_incompat",
        Superblock,
        80,
        4,
        LeU32,
        Always,
        "erofs_super_block.feature_incompat"
    ),
    field!(
        "erofs.superblock.lz4_max_distance",
        Superblock,
        84,
        2,
        LeU16,
        WithoutCompressionConfig,
        "erofs_super_block.u1.lz4_max_distance"
    ),
    field!(
        "erofs.superblock.available_compr_algs",
        Superblock,
        84,
        2,
        LeU16,
        WithCompressionConfig,
        "erofs_super_block.u1.available_compr_algs"
    ),
    field!(
        "erofs.superblock.extra_devices",
        Superblock,
        86,
        2,
        LeU16,
        Always,
        "erofs_super_block.extra_devices"
    ),
    field!(
        "erofs.superblock.devt_slotoff",
        Superblock,
        88,
        2,
        LeU16,
        Always,
        "erofs_super_block.devt_slotoff"
    ),
    field!(
        "erofs.superblock.dirblkbits",
        Superblock,
        90,
        1,
        U8,
        Always,
        "erofs_super_block.dirblkbits"
    ),
    field!(
        "erofs.superblock.xattr_prefix_count",
        Superblock,
        91,
        1,
        U8,
        Always,
        "erofs_super_block.xattr_prefix_count"
    ),
    field!(
        "erofs.superblock.xattr_prefix_start",
        Superblock,
        92,
        4,
        LeU32,
        Always,
        "erofs_super_block.xattr_prefix_start"
    ),
    field!(
        "erofs.superblock.packed_nid",
        Superblock,
        96,
        8,
        LeU64,
        Always,
        "erofs_super_block.packed_nid"
    ),
    field!(
        "erofs.superblock.xattr_filter_reserved",
        Superblock,
        104,
        1,
        U8,
        Always,
        "erofs_super_block.xattr_filter_reserved"
    ),
    field!(
        "erofs.superblock.ishare_xattr_prefix_id",
        Superblock,
        105,
        1,
        U8,
        Always,
        "erofs_super_block.ishare_xattr_prefix_id"
    ),
    field!(
        "erofs.superblock.reserved",
        Superblock,
        106,
        2,
        Bytes,
        Always,
        "erofs_super_block.reserved"
    ),
    field!(
        "erofs.superblock.build_time",
        Superblock,
        108,
        4,
        LeU32,
        Always,
        "erofs_super_block.build_time"
    ),
    field!(
        "erofs.superblock.rootnid_8b",
        Superblock,
        112,
        8,
        LeU64,
        With48Bit,
        "erofs_super_block.rootnid_8b"
    ),
    field!(
        "erofs.superblock.reserved2",
        Superblock,
        120,
        8,
        Bytes,
        Always,
        "erofs_super_block.reserved2"
    ),
    field!(
        "erofs.superblock.metabox_nid",
        Superblock,
        128,
        8,
        LeU64,
        Superblock144,
        "erofs_super_block.metabox_nid"
    ),
    field!(
        "erofs.superblock.reserved3",
        Superblock,
        136,
        8,
        Bytes,
        Superblock144,
        "erofs_super_block.reserved3"
    ),
    field!(
        "erofs.inode.compact.i_format",
        CompactInode,
        0,
        2,
        LeU16,
        Always,
        "erofs_inode_compact.i_format"
    ),
    field!(
        "erofs.inode.compact.i_xattr_icount",
        CompactInode,
        2,
        2,
        LeU16,
        Always,
        "erofs_inode_compact.i_xattr_icount"
    ),
    field!(
        "erofs.inode.compact.i_mode",
        CompactInode,
        4,
        2,
        LeU16,
        Always,
        "erofs_inode_compact.i_mode"
    ),
    field!(
        "erofs.inode.compact.i_nb",
        CompactInode,
        6,
        2,
        LeU16,
        Always,
        "erofs_inode_compact.i_nb"
    ),
    field!(
        "erofs.inode.compact.i_size",
        CompactInode,
        8,
        4,
        LeU32,
        Always,
        "erofs_inode_compact.i_size"
    ),
    field!(
        "erofs.inode.compact.i_mtime",
        CompactInode,
        12,
        4,
        LeU32,
        Always,
        "erofs_inode_compact.i_mtime"
    ),
    field!(
        "erofs.inode.compact.i_u",
        CompactInode,
        16,
        4,
        LeU32,
        Always,
        "erofs_inode_compact.i_u"
    ),
    field!(
        "erofs.inode.compact.i_ino",
        CompactInode,
        20,
        4,
        LeU32,
        Always,
        "erofs_inode_compact.i_ino"
    ),
    field!(
        "erofs.inode.compact.i_uid",
        CompactInode,
        24,
        2,
        LeU16,
        Always,
        "erofs_inode_compact.i_uid"
    ),
    field!(
        "erofs.inode.compact.i_gid",
        CompactInode,
        26,
        2,
        LeU16,
        Always,
        "erofs_inode_compact.i_gid"
    ),
    field!(
        "erofs.inode.compact.i_reserved",
        CompactInode,
        28,
        4,
        Bytes,
        Always,
        "erofs_inode_compact.i_reserved"
    ),
    field!(
        "erofs.inode.extended.i_format",
        ExtendedInode,
        0,
        2,
        LeU16,
        Always,
        "erofs_inode_extended.i_format"
    ),
    field!(
        "erofs.inode.extended.i_xattr_icount",
        ExtendedInode,
        2,
        2,
        LeU16,
        Always,
        "erofs_inode_extended.i_xattr_icount"
    ),
    field!(
        "erofs.inode.extended.i_mode",
        ExtendedInode,
        4,
        2,
        LeU16,
        Always,
        "erofs_inode_extended.i_mode"
    ),
    field!(
        "erofs.inode.extended.i_nb",
        ExtendedInode,
        6,
        2,
        LeU16,
        Always,
        "erofs_inode_extended.i_nb"
    ),
    field!(
        "erofs.inode.extended.i_size",
        ExtendedInode,
        8,
        8,
        LeU64,
        Always,
        "erofs_inode_extended.i_size"
    ),
    field!(
        "erofs.inode.extended.i_u",
        ExtendedInode,
        16,
        4,
        LeU32,
        Always,
        "erofs_inode_extended.i_u"
    ),
    field!(
        "erofs.inode.extended.i_ino",
        ExtendedInode,
        20,
        4,
        LeU32,
        Always,
        "erofs_inode_extended.i_ino"
    ),
    field!(
        "erofs.inode.extended.i_uid",
        ExtendedInode,
        24,
        4,
        LeU32,
        Always,
        "erofs_inode_extended.i_uid"
    ),
    field!(
        "erofs.inode.extended.i_gid",
        ExtendedInode,
        28,
        4,
        LeU32,
        Always,
        "erofs_inode_extended.i_gid"
    ),
    field!(
        "erofs.inode.extended.i_mtime",
        ExtendedInode,
        32,
        8,
        LeU64,
        Always,
        "erofs_inode_extended.i_mtime"
    ),
    field!(
        "erofs.inode.extended.i_mtime_nsec",
        ExtendedInode,
        40,
        4,
        LeU32,
        Always,
        "erofs_inode_extended.i_mtime_nsec"
    ),
    field!(
        "erofs.inode.extended.i_nlink",
        ExtendedInode,
        44,
        4,
        LeU32,
        Always,
        "erofs_inode_extended.i_nlink"
    ),
    field!(
        "erofs.inode.extended.i_reserved2",
        ExtendedInode,
        48,
        16,
        Bytes,
        Always,
        "erofs_inode_extended.i_reserved2"
    ),
    field!(
        "erofs.dirent.nid",
        Dirent,
        0,
        8,
        LeU64,
        Always,
        "erofs_dirent.nid"
    ),
    field!(
        "erofs.dirent.nameoff",
        Dirent,
        8,
        2,
        LeU16,
        Always,
        "erofs_dirent.nameoff"
    ),
    field!(
        "erofs.dirent.file_type",
        Dirent,
        10,
        1,
        U8,
        Always,
        "erofs_dirent.file_type"
    ),
    field!(
        "erofs.dirent.reserved",
        Dirent,
        11,
        1,
        U8,
        Always,
        "erofs_dirent.reserved"
    ),
    field!(
        "erofs.super.extension.raw",
        SuperblockExtension,
        0,
        16,
        Bytes,
        Dynamic,
        "erofs_super_block extension slot"
    ),
    field!(
        "erofs.device.tag",
        DeviceSlot,
        0,
        64,
        Bytes,
        WithDeviceTable,
        "erofs_deviceslot.tag"
    ),
    field!(
        "erofs.device.blocks_lo",
        DeviceSlot,
        64,
        4,
        LeU32,
        WithDeviceTable,
        "erofs_deviceslot.blocks_lo"
    ),
    field!(
        "erofs.device.uniaddr_lo",
        DeviceSlot,
        68,
        4,
        LeU32,
        WithDeviceTable,
        "erofs_deviceslot.uniaddr_lo"
    ),
    field!(
        "erofs.device.blocks_hi",
        DeviceSlot,
        72,
        2,
        LeU16,
        With48Bit,
        "erofs_deviceslot.blocks_hi"
    ),
    field!(
        "erofs.device.uniaddr_hi",
        DeviceSlot,
        74,
        2,
        LeU16,
        With48Bit,
        "erofs_deviceslot.uniaddr_hi"
    ),
    field!(
        "erofs.device.reserved",
        DeviceSlot,
        76,
        52,
        Bytes,
        WithDeviceTable,
        "erofs_deviceslot.reserved"
    ),
    field!(
        "erofs.chunk.block",
        ChunkEntry,
        0,
        4,
        LeU32,
        Dynamic,
        "__le32 chunk block address"
    ),
    field!(
        "erofs.chunk.startblk_hi",
        ChunkEntry,
        0,
        2,
        LeU16,
        Dynamic,
        "erofs_inode_chunk_index.startblk_hi"
    ),
    field!(
        "erofs.chunk.device_id",
        ChunkEntry,
        2,
        2,
        LeU16,
        Dynamic,
        "erofs_inode_chunk_index.device_id"
    ),
    field!(
        "erofs.chunk.startblk_lo",
        ChunkEntry,
        4,
        4,
        LeU32,
        Dynamic,
        "erofs_inode_chunk_index.startblk_lo"
    ),
    field!(
        "erofs.xattr.header.name_filter",
        XattrHeader,
        0,
        4,
        LeU32,
        Dynamic,
        "erofs_xattr_ibody_header.h_name_filter"
    ),
    field!(
        "erofs.xattr.header.shared_count",
        XattrHeader,
        4,
        1,
        U8,
        Dynamic,
        "erofs_xattr_ibody_header.h_shared_count"
    ),
    field!(
        "erofs.xattr.header.reserved",
        XattrHeader,
        5,
        7,
        Bytes,
        Dynamic,
        "erofs_xattr_ibody_header.h_reserved2"
    ),
    field!(
        "erofs.xattr.shared_id",
        SharedXattrId,
        0,
        4,
        LeU32,
        Dynamic,
        "erofs_xattr_ibody_header.h_shared_xattrs[]"
    ),
    field!(
        "erofs.xattr.entry.name_len",
        XattrEntry,
        0,
        1,
        U8,
        Dynamic,
        "erofs_xattr_entry.e_name_len"
    ),
    field!(
        "erofs.xattr.entry.name_index",
        XattrEntry,
        1,
        1,
        U8,
        Dynamic,
        "erofs_xattr_entry.e_name_index"
    ),
    field!(
        "erofs.xattr.entry.value_size",
        XattrEntry,
        2,
        2,
        LeU16,
        Dynamic,
        "erofs_xattr_entry.e_value_size"
    ),
    field!(
        "erofs.xattr.entry.name",
        XattrEntry,
        4,
        0,
        Bytes,
        Dynamic,
        "erofs_xattr_entry.e_name"
    ),
    field!(
        "erofs.xattr.entry.value",
        XattrEntry,
        4,
        0,
        Bytes,
        Dynamic,
        "erofs_xattr_entry value"
    ),
    field!(
        "erofs.xattr.prefix.length",
        XattrLongPrefix,
        0,
        2,
        LeU16,
        WithXattrPrefixes,
        "metadata record length"
    ),
    field!(
        "erofs.xattr.prefix.base_index",
        XattrLongPrefix,
        2,
        1,
        U8,
        WithXattrPrefixes,
        "erofs_xattr_long_prefix.base_index"
    ),
    field!(
        "erofs.xattr.prefix.infix",
        XattrLongPrefix,
        3,
        0,
        Bytes,
        Dynamic,
        "erofs_xattr_long_prefix.infix"
    ),
    field!(
        "erofs.compression.config.length",
        CompressionConfig,
        0,
        2,
        LeU16,
        WithCompressionConfig,
        "metadata record length"
    ),
    field!(
        "erofs.compression.config.payload",
        CompressionConfig,
        2,
        0,
        Bytes,
        Dynamic,
        "compression configuration payload"
    ),
    field!(
        "erofs.compression.map.fragmentoff",
        CompressionMap,
        0,
        4,
        LeU32,
        Dynamic,
        "z_erofs_map_header.h_fragmentoff"
    ),
    field!(
        "erofs.compression.map.idata_size",
        CompressionMap,
        2,
        2,
        LeU16,
        Dynamic,
        "z_erofs_map_header.h_idata_size"
    ),
    field!(
        "erofs.compression.map.extents_lo",
        CompressionMap,
        0,
        4,
        LeU32,
        Dynamic,
        "z_erofs_map_header.h_extents_lo"
    ),
    field!(
        "erofs.compression.map.advise",
        CompressionMap,
        4,
        2,
        LeU16,
        Dynamic,
        "z_erofs_map_header.h_advise"
    ),
    field!(
        "erofs.compression.map.algorithmtype",
        CompressionMap,
        6,
        1,
        U8,
        Dynamic,
        "z_erofs_map_header.h_algorithmtype"
    ),
    field!(
        "erofs.compression.map.clusterbits",
        CompressionMap,
        7,
        1,
        U8,
        Dynamic,
        "z_erofs_map_header.h_clusterbits"
    ),
    field!(
        "erofs.compression.map.extents_hi",
        CompressionMap,
        6,
        2,
        LeU16,
        Dynamic,
        "z_erofs_map_header.h_extents_hi"
    ),
    field!(
        "erofs.compression.index.advise",
        CompressionIndex,
        0,
        2,
        LeU16,
        Dynamic,
        "z_erofs_lcluster_index.di_advise"
    ),
    field!(
        "erofs.compression.index.clusterofs",
        CompressionIndex,
        2,
        2,
        LeU16,
        Dynamic,
        "z_erofs_lcluster_index.di_clusterofs"
    ),
    field!(
        "erofs.compression.index.blkaddr",
        CompressionIndex,
        4,
        4,
        LeU32,
        Dynamic,
        "z_erofs_lcluster_index.di_u.blkaddr"
    ),
    field!(
        "erofs.compression.index.delta0",
        CompressionIndex,
        4,
        2,
        LeU16,
        Dynamic,
        "z_erofs_lcluster_index.di_u.delta[0]"
    ),
    field!(
        "erofs.compression.index.delta1",
        CompressionIndex,
        6,
        2,
        LeU16,
        Dynamic,
        "z_erofs_lcluster_index.di_u.delta[1]"
    ),
    field!(
        "erofs.compression.compact_pack.raw",
        CompressionCompactPack,
        0,
        0,
        Bytes,
        Dynamic,
        "compact lcluster index pack"
    ),
    field!(
        "erofs.compression.extent.plen",
        CompressionExtent,
        0,
        4,
        LeU32,
        Dynamic,
        "z_erofs_extent.plen"
    ),
    field!(
        "erofs.compression.extent.pstart_lo",
        CompressionExtent,
        4,
        4,
        LeU32,
        Dynamic,
        "z_erofs_extent.pstart_lo"
    ),
    field!(
        "erofs.compression.extent.pstart_hi",
        CompressionExtent,
        8,
        4,
        LeU32,
        Dynamic,
        "z_erofs_extent.pstart_hi"
    ),
    field!(
        "erofs.compression.extent.lstart_lo",
        CompressionExtent,
        12,
        4,
        LeU32,
        Dynamic,
        "z_erofs_extent.lstart_lo"
    ),
    field!(
        "erofs.compression.extent.lstart_hi",
        CompressionExtent,
        16,
        4,
        LeU32,
        Dynamic,
        "z_erofs_extent.lstart_hi"
    ),
    field!(
        "erofs.compression.extent.reserved",
        CompressionExtent,
        20,
        12,
        Bytes,
        Dynamic,
        "z_erofs_extent.reserved"
    ),
];

/// Looks up a field by stable ID.
pub fn field_by_id(id: &str) -> Option<&'static FieldDef> {
    FIELDS.iter().find(|field| field.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_identity_is_pinned() {
        assert_eq!(SCHEMA_IDENTITY.api, "erofs-abi-schema/v1");
        assert_eq!(SCHEMA_IDENTITY.linux_commit.len(), 40);
        assert!(SCHEMA_IDENTITY.digest.starts_with("sha256:"));
    }

    #[test]
    fn registered_fields_fit_their_pinned_structures() {
        for field in FIELDS {
            let size = match field.structure {
                StructureId::Superblock => 144,
                StructureId::CompactInode => 32,
                StructureId::ExtendedInode => 64,
                StructureId::Dirent => 12,
                StructureId::SuperblockExtension => 16,
                StructureId::DeviceSlot => 128,
                StructureId::ChunkEntry
                | StructureId::CompressionMap
                | StructureId::CompressionIndex => 8,
                StructureId::XattrHeader => 12,
                StructureId::SharedXattrId => 4,
                StructureId::XattrEntry
                | StructureId::XattrLongPrefix
                | StructureId::CompressionConfig
                | StructureId::CompressionCompactPack
                | StructureId::CompressionExtent => 64,
            };
            assert!(field.storage.end().unwrap() <= size, "{}", field.id);
            assert!(field.storage.len <= 64, "{}", field.id);
            assert_eq!(field_by_id(field.id), Some(field));
        }
    }

    #[test]
    fn stable_field_ids_are_unique() {
        for (index, field) in FIELDS.iter().enumerate() {
            assert!(
                !FIELDS[index + 1..].iter().any(|other| other.id == field.id),
                "duplicate field ID {}",
                field.id
            );
        }
    }
}
