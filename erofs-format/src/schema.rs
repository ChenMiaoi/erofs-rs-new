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
    "sha256:ad535d233291854d30a260a9abbf78531c0e2dc4932bda6c3ccefe0374b6ad23";

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

/// All fields supported by the M1 locator.
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
            };
            assert!(field.storage.end().unwrap() <= size, "{}", field.id);
            assert!(field.storage.len <= 16, "{}", field.id);
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
