//! Bounded, tolerant location of supported EROFS field occurrences.

use crate::schema::{Encoding, FieldDef, Predicate, StructureId};
use crate::{
    CHUNK_FORMAT_ALL, CHUNK_FORMAT_INDEXES, ReadAt, SUPERBLOCK_BASE_SIZE, SUPERBLOCK_EXTSLOT_SIZE,
    SUPERBLOCK_OFFSET, Span, le_u16, le_u32, le_u64, primary_inode_offset,
};

const FEATURE_INCOMPAT_COMPR_CFGS: u32 = 0x0000_0002;
const FEATURE_INCOMPAT_48BIT: u32 = 0x0000_0080;
const FEATURE_INCOMPAT_DEVICE_TABLE: u32 = 0x0000_0008;
const FEATURE_INCOMPAT_XATTR_PREFIXES: u32 = 0x0000_0040;
const FEATURE_INCOMPAT_METABOX: u32 = 0x0000_0100;
const INODE_EXTENDED_BIT: u16 = 0x0001;
const INODE_LAYOUT_MASK: u16 = 0x000e;
const INODE_LAYOUT_SHIFT: u32 = 1;
const LAYOUT_FLAT_PLAIN: u16 = 0;
const LAYOUT_FLAT_INLINE: u16 = 2;
const COMPACT_INODE_SIZE: u64 = 32;
const LAYOUT_COMPRESSED_FULL: u16 = 1;
const LAYOUT_COMPRESSED_COMPACT: u16 = 3;
const LAYOUT_CHUNK: u16 = 4;
const XATTR_HEADER_SIZE: u64 = 12;
const DEVICE_SLOT_SIZE: u64 = 128;
const ADVISE_EXTENTS: u16 = 1;
const EXTENDED_INODE_SIZE: u64 = 64;
const DIRENT_SIZE: u64 = 12;
const MODE_DIRECTORY: u16 = 0o040000;
const MODE_TYPE_MASK: u16 = 0o170000;
const ALL_FEATURE_INCOMPAT: u32 = 0x0000_01ff;

/// Structural validation policy for a snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseMode {
    /// Enforce pinned feature, reserved-bit, and parent constraints.
    Strict,
    /// Continue while the next byte range remains unambiguous and bounded.
    Tolerant,
}

/// Metadata address space used by an object selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataSpace {
    /// Primary metadata anchored by `meta_blkaddr`.
    Primary,
    /// Logical metadata inside the metabox inode.
    Metabox,
}

/// Canonical object selector supported by M1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectRef {
    /// The only superblock.
    Superblock,
    /// An inode slot in a metadata address space.
    Inode { space: MetadataSpace, nid: u64 },
    /// A dirent in a logical block of a directory inode.
    Dirent {
        /// Directory inode selector.
        directory: u64,
        /// Logical directory block index.
        block: u64,
        /// Dirent index within the directory block.
        index: u32,
    },
    /// One raw 16-byte superblock extension slot.
    SuperblockExtension { index: u8 },
    /// One extra-device descriptor (zero-based).
    DeviceSlot { index: u16 },
    /// One chunk block/index entry.
    Chunk { inode: u64, index: u64 },
    /// Inline xattr header following an inode.
    XattrHeader { inode: u64 },
    /// Shared xattr ID inside an inline xattr header.
    SharedXattrId { inode: u64, index: u32 },
    /// Inline xattr entry after the shared-ID array.
    InlineXattr { inode: u64, index: u32 },
    /// Long xattr prefix metadata record.
    XattrLongPrefix { index: u8 },
    /// Compression configuration record selected by algorithm ID.
    CompressionConfig { algorithm: u8 },
    /// Compressed inode map header.
    CompressionMap { inode: u64 },
    /// Full compressed lcluster index.
    CompressionIndex { inode: u64, index: u64 },
    /// Compact compressed index pack.
    CompressionCompactPack { inode: u64, index: u64 },
    /// Compressed extent record.
    CompressionExtent { inode: u64, index: u64 },
}

/// Decoded field value without heap allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedValue {
    /// Unsigned scalar value.
    Unsigned(u64),
    /// Fixed or bounded variable bytes, with the valid prefix indicated by `len`.
    Bytes { bytes: [u8; 64], len: u8 },
}

/// One read on which an occurrence location depends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DependencyRead {
    /// Stable dependency field ID.
    pub field: &'static str,
    /// Absolute byte range read.
    pub span: Span,
    /// Decoded unsigned value.
    pub value: u64,
}
type Provenance = [Option<DependencyRead>; 6];
type LocatedObject = (u64, StructureId, Provenance, Option<u64>);

/// A resolved field instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldOccurrence {
    /// Static field definition.
    pub field: &'static FieldDef,
    /// Canonical object selector.
    pub object: ObjectRef,
    /// Absolute field range.
    pub span: Span,
    /// Original bytes, with the valid prefix indicated by `raw_len`.
    pub raw: [u8; 64],
    /// Number of valid bytes in `raw`.
    pub raw_len: u8,
    /// Decoded field value.
    pub value: DecodedValue,
    /// Location dependency reads, packed at the start.
    pub provenance: [Option<DependencyRead>; 6],
}

/// Versioned capability that is known but not implemented by this locator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    /// Metabox metadata address space.
    Metabox,
    /// Compressed directory data mapping.
    CompressedDirectory,
    /// Chunk-based directory data mapping.
    ChunkDirectory,
}

/// Structured locator failure.
#[derive(Debug)]
pub enum LocateError<E> {
    /// Backend read failure.
    Read(E),
    /// Checked address arithmetic overflowed.
    Overflow,
    /// A required range is outside the image.
    OutOfBounds { span: Span, image_len: u64 },
    /// Field and object refer to different structures.
    ObjectMismatch {
        field_structure: StructureId,
        object: ObjectRef,
    },
    /// A conditional semantic view is inactive.
    AbsentByFeature {
        field: &'static str,
        predicate: Predicate,
    },
    /// The parent structure is malformed and cannot be located safely.
    UnresolvedParent {
        object: ObjectRef,
        reason: &'static str,
    },
    /// Strict structural validation rejected the parent.
    InvalidStructure {
        object: ObjectRef,
        reason: &'static str,
    },
    /// The requested capability is outside M1.
    UnsupportedCapability(Capability),
}

/// Parsed superblock dependencies required for supported object location.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuperblockContext {
    /// Filesystem magic, retained for diagnostics.
    pub magic: u32,
    /// Filesystem block-size shift.
    pub blkszbits: u8,
    /// Number of 16-byte extension slots.
    pub ext_slots: u8,
    /// Incompatible feature bits.
    pub feature_incompat: u32,
    /// Primary metadata starting block.
    pub meta_blkaddr: u32,
    /// Compatible feature bits.
    pub feature_compat: u32,
    /// Shared xattr starting block.
    pub xattr_blkaddr: u32,
    /// Extra-device count.
    pub extra_devices: u16,
    /// Device-table slot offset.
    pub devt_slotoff: u16,
    /// Long-prefix record count.
    pub xattr_prefix_count: u8,
    /// Long-prefix logical start in 4-byte units.
    pub xattr_prefix_start: u32,
}

/// Read-only locator bound to one image.
pub struct Locator<'a, R: ReadAt> {
    image: &'a R,
    superblock: SuperblockContext,
    mode: ParseMode,
}

impl<'a, R: ReadAt> Locator<'a, R> {
    /// Opens an image in strict mode.
    pub fn new(image: &'a R) -> Result<Self, LocateError<R::Error>> {
        Self::with_mode(image, ParseMode::Strict)
    }

    /// Opens an image with an explicit structural validation policy.
    pub fn with_mode(image: &'a R, mode: ParseMode) -> Result<Self, LocateError<R::Error>> {
        let span = Span::new(SUPERBLOCK_OFFSET, SUPERBLOCK_BASE_SIZE)
            .map_err(|_| LocateError::Overflow)?;
        ensure_span::<R::Error>(span, image.len())?;
        let mut prefix = [0; 104];
        image
            .read_exact_at(SUPERBLOCK_OFFSET, &mut prefix)
            .map_err(LocateError::Read)?;
        let superblock = SuperblockContext {
            magic: le_u32(prefix[..4].try_into().unwrap()),
            feature_compat: le_u32(prefix[8..12].try_into().unwrap()),
            blkszbits: prefix[12],
            ext_slots: prefix[13],
            meta_blkaddr: le_u32(prefix[40..44].try_into().unwrap()),
            xattr_blkaddr: le_u32(prefix[44..48].try_into().unwrap()),
            feature_incompat: le_u32(prefix[80..84].try_into().unwrap()),
            extra_devices: le_u16(prefix[86..88].try_into().unwrap()),
            devt_slotoff: le_u16(prefix[88..90].try_into().unwrap()),
            xattr_prefix_count: prefix[91],
            xattr_prefix_start: le_u32(prefix[92..96].try_into().unwrap()),
        };
        if mode == ParseMode::Strict {
            if superblock.magic != crate::SUPERBLOCK_MAGIC {
                return Err(LocateError::InvalidStructure {
                    object: ObjectRef::Superblock,
                    reason: "invalid EROFS magic",
                });
            }
            if superblock.feature_incompat & !ALL_FEATURE_INCOMPAT != 0 {
                return Err(LocateError::InvalidStructure {
                    object: ObjectRef::Superblock,
                    reason: "unknown incompatible feature bits",
                });
            }
            if !(9..=63).contains(&superblock.blkszbits) {
                return Err(LocateError::InvalidStructure {
                    object: ObjectRef::Superblock,
                    reason: "invalid block-size shift",
                });
            }
        }
        Ok(Self {
            image,
            superblock,
            mode,
        })
    }

    /// Returns the parsed location dependencies.
    pub const fn superblock(&self) -> SuperblockContext {
        self.superblock
    }

    /// Resolves one field definition against one canonical object selector.
    pub fn locate(
        &self,
        object: ObjectRef,
        field: &'static FieldDef,
    ) -> Result<FieldOccurrence, LocateError<R::Error>> {
        let (base, structure, provenance, dynamic_len) = match object {
            ObjectRef::Superblock => (SUPERBLOCK_OFFSET, StructureId::Superblock, [None; 6], None),
            ObjectRef::Inode { space, nid } => self.locate_inode(space, nid)?,
            ObjectRef::Dirent {
                directory,
                block,
                index,
            } => self.locate_dirent(directory, block, index)?,
            ObjectRef::SuperblockExtension { index } => self.locate_extension(index)?,
            ObjectRef::DeviceSlot { index } => self.locate_device(index)?,
            ObjectRef::Chunk { inode, index } => self.locate_chunk(inode, index)?,
            ObjectRef::XattrHeader { inode } => self.locate_xattr_header(inode)?,
            ObjectRef::SharedXattrId { inode, index } => {
                self.locate_shared_xattr_id(inode, index)?
            }
            ObjectRef::InlineXattr { inode, index } => self.locate_inline_xattr(inode, index)?,
            ObjectRef::XattrLongPrefix { index } => self.locate_xattr_prefix(index)?,
            ObjectRef::CompressionConfig { algorithm } => {
                self.locate_compression_config(algorithm)?
            }
            ObjectRef::CompressionMap { inode } => self.locate_compression_map(inode)?,
            ObjectRef::CompressionIndex { inode, index } => {
                self.locate_compression_index(inode, index)?
            }
            ObjectRef::CompressionCompactPack { inode, index } => {
                self.locate_compact_pack(inode, index)?
            }
            ObjectRef::CompressionExtent { inode, index } => {
                self.locate_compression_extent(inode, index)?
            }
        };
        if field.structure != structure {
            return Err(LocateError::ObjectMismatch {
                field_structure: field.structure,
                object,
            });
        }
        self.check_presence(field)?;
        self.check_object_field(structure, dynamic_len, field, object)?;
        let relative = if field.storage.len == 0 && field.id.ends_with(".value") {
            4 + u64::from(self.read_u8(base)?)
        } else {
            field.storage.offset
        };
        let offset = base.checked_add(relative).ok_or(LocateError::Overflow)?;
        let len = self.dynamic_field_len(base, field, dynamic_len)?;
        let span = Span::new(offset, len).map_err(|_| LocateError::Overflow)?;
        ensure_span::<R::Error>(span, self.image.len())?;
        let raw_len = u8::try_from(len).map_err(|_| LocateError::Overflow)?;
        let mut raw = [0; 64];
        self.image
            .read_exact_at(offset, &mut raw[..usize::from(raw_len)])
            .map_err(LocateError::Read)?;
        let value = decode(field.encoding, raw, raw_len);
        Ok(FieldOccurrence {
            field,
            object,
            span,
            raw,
            raw_len,
            value,
            provenance,
        })
    }

    fn check_presence(&self, field: &'static FieldDef) -> Result<(), LocateError<R::Error>> {
        let enabled = match field.presence {
            Predicate::Always => true,
            Predicate::Without48Bit => {
                self.superblock.feature_incompat & FEATURE_INCOMPAT_48BIT == 0
            }
            Predicate::With48Bit => self.superblock.feature_incompat & FEATURE_INCOMPAT_48BIT != 0,
            Predicate::WithoutCompressionConfig => {
                self.superblock.feature_incompat & FEATURE_INCOMPAT_COMPR_CFGS == 0
            }
            Predicate::WithCompressionConfig => {
                self.superblock.feature_incompat & FEATURE_INCOMPAT_COMPR_CFGS != 0
            }
            Predicate::Superblock144 => {
                SUPERBLOCK_BASE_SIZE
                    + u64::from(self.superblock.ext_slots) * SUPERBLOCK_EXTSLOT_SIZE
                    >= 144
            }
            Predicate::WithMetabox => {
                self.superblock.feature_incompat & FEATURE_INCOMPAT_METABOX != 0
            }
            Predicate::WithXattrPrefixes => {
                self.superblock.feature_incompat & FEATURE_INCOMPAT_XATTR_PREFIXES != 0
            }
            Predicate::WithDeviceTable => {
                self.superblock.feature_incompat & FEATURE_INCOMPAT_DEVICE_TABLE != 0
            }
            Predicate::Dynamic => true,
        };
        if enabled {
            Ok(())
        } else {
            Err(LocateError::AbsentByFeature {
                field: field.id,
                predicate: field.presence,
            })
        }
    }

    fn check_object_field(
        &self,
        structure: StructureId,
        object_len: Option<u64>,
        field: &FieldDef,
        object: ObjectRef,
    ) -> Result<(), LocateError<R::Error>> {
        let compatible = match structure {
            StructureId::ChunkEntry if object_len == Some(4) => field.id == "erofs.chunk.block",
            StructureId::ChunkEntry if object_len == Some(8) => {
                field.id != "erofs.chunk.block"
                    && (field.id != "erofs.chunk.startblk_hi" || self.chunk_uses_48bit(object)?)
            }
            StructureId::CompressionExtent => field.storage.offset < object_len.unwrap_or(0),
            _ => true,
        };
        if compatible {
            Ok(())
        } else {
            Err(LocateError::ObjectMismatch {
                field_structure: field.structure,
                object,
            })
        }
    }

    fn chunk_uses_48bit(&self, object: ObjectRef) -> Result<bool, LocateError<R::Error>> {
        let ObjectRef::Chunk { inode, .. } = object else {
            return Ok(false);
        };
        let (base, _, _, _) = self.inode_tail(inode)?;
        Ok(self.read_u16(base + 16)? & crate::CHUNK_FORMAT_48BIT != 0)
    }

    fn locate_inode(
        &self,
        space: MetadataSpace,
        nid: u64,
    ) -> Result<LocatedObject, LocateError<R::Error>> {
        let offset = match space {
            MetadataSpace::Primary => {
                primary_inode_offset(self.superblock.meta_blkaddr, self.superblock.blkszbits, nid)
                    .map_err(|_| LocateError::Overflow)?
            }
            MetadataSpace::Metabox => {
                if self.superblock.feature_incompat & FEATURE_INCOMPAT_METABOX == 0 {
                    return Err(LocateError::UnsupportedCapability(Capability::Metabox));
                }
                nid.checked_mul(crate::INODE_SLOT_SIZE)
                    .ok_or(LocateError::Overflow)?
            }
        };
        let format_span = Span::new(offset, 2).map_err(|_| LocateError::Overflow)?;
        ensure_span::<R::Error>(format_span, self.image.len())?;
        let format = self.read_u16(offset)?;
        if self.mode == ParseMode::Strict && format & !0x001f != 0 {
            return Err(LocateError::InvalidStructure {
                object: ObjectRef::Inode { space, nid },
                reason: "inode format has reserved bits set",
            });
        }
        let (structure, size) = if format & INODE_EXTENDED_BIT == 0 {
            (StructureId::CompactInode, COMPACT_INODE_SIZE)
        } else {
            (StructureId::ExtendedInode, EXTENDED_INODE_SIZE)
        };
        ensure_span::<R::Error>(
            Span::new(offset, size).map_err(|_| LocateError::Overflow)?,
            self.image.len(),
        )?;
        Ok((
            offset,
            structure,
            self.inode_provenance(format_span, format, nid),
            None,
        ))
    }

    fn locate_extension(&self, index: u8) -> Result<LocatedObject, LocateError<R::Error>> {
        if index >= self.superblock.ext_slots {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::SuperblockExtension { index },
                reason: "extension slot is outside sb_extslots",
            });
        }
        let base = SUPERBLOCK_OFFSET
            .checked_add(SUPERBLOCK_BASE_SIZE)
            .and_then(|v| v.checked_add(u64::from(index) * SUPERBLOCK_EXTSLOT_SIZE))
            .ok_or(LocateError::Overflow)?;
        Ok((base, StructureId::SuperblockExtension, [None; 6], None))
    }

    fn locate_device(&self, index: u16) -> Result<LocatedObject, LocateError<R::Error>> {
        if self.superblock.feature_incompat & FEATURE_INCOMPAT_DEVICE_TABLE == 0 {
            return Err(LocateError::AbsentByFeature {
                field: "erofs.device.tag",
                predicate: Predicate::WithDeviceTable,
            });
        }
        if index >= self.superblock.extra_devices {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::DeviceSlot { index },
                reason: "device index is outside extra_devices",
            });
        }
        let base = u64::from(self.superblock.devt_slotoff)
            .checked_mul(DEVICE_SLOT_SIZE)
            .and_then(|v| v.checked_add(u64::from(index) * DEVICE_SLOT_SIZE))
            .ok_or(LocateError::Overflow)?;
        ensure_span::<R::Error>(
            Span::new(base, DEVICE_SLOT_SIZE).map_err(|_| LocateError::Overflow)?,
            self.image.len(),
        )?;
        Ok((base, StructureId::DeviceSlot, [None; 6], None))
    }

    fn inode_tail(&self, inode: u64) -> Result<(u64, u64, u16, u64), LocateError<R::Error>> {
        let (base, structure, _, _) = self.locate_inode(MetadataSpace::Primary, inode)?;
        let inode_size = if structure == StructureId::CompactInode {
            COMPACT_INODE_SIZE
        } else {
            EXTENDED_INODE_SIZE
        };
        let format = self.read_u16(base)?;
        let count = u64::from(self.read_u16(base + 2)?);
        let xattr_size = if count == 0 {
            0
        } else {
            XATTR_HEADER_SIZE + (count - 1) * 4
        };
        let end = base
            .checked_add(inode_size)
            .and_then(|v| v.checked_add(xattr_size))
            .ok_or(LocateError::Overflow)?;
        Ok((base, end, format, xattr_size))
    }

    fn locate_chunk(&self, inode: u64, index: u64) -> Result<LocatedObject, LocateError<R::Error>> {
        let (base, end, format, _) = self.inode_tail(inode)?;
        if (format & INODE_LAYOUT_MASK) >> INODE_LAYOUT_SHIFT != LAYOUT_CHUNK {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::Chunk { inode, index },
                reason: "inode is not chunk based",
            });
        }
        let chunk_format = self.read_u16(base + 16)?;
        if self.mode == ParseMode::Strict && chunk_format & !CHUNK_FORMAT_ALL != 0 {
            return Err(LocateError::InvalidStructure {
                object: ObjectRef::Chunk { inode, index },
                reason: "chunk format has reserved bits set",
            });
        }
        let unit = if chunk_format & CHUNK_FORMAT_INDEXES != 0 {
            8
        } else {
            4
        };
        let table = align_up(end, unit)?;
        let entry = table
            .checked_add(index.checked_mul(unit).ok_or(LocateError::Overflow)?)
            .ok_or(LocateError::Overflow)?;
        let size = if self.read_u16(base)? & INODE_EXTENDED_BIT == 0 {
            u64::from(self.read_u32(base + 8)?)
        } else {
            self.read_u64(base + 8)?
        };
        let chunkbits = u32::from(self.superblock.blkszbits)
            + u32::from(chunk_format & crate::CHUNK_FORMAT_BLKBITS_MASK);
        // blkszbits and the chunk-format blkbits are image controlled, so the
        // chunk-size shift can exceed 63; fail instead of wrapping the shift.
        let chunk_size = 1_u64.checked_shl(chunkbits).ok_or(LocateError::Overflow)?;
        // The checked shift above proves chunkbits < 64, so this shift is safe.
        let chunks = size
            .checked_add(chunk_size - 1)
            .ok_or(LocateError::Overflow)?
            >> chunkbits;
        if index >= chunks {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::Chunk { inode, index },
                reason: "chunk index is outside inode size",
            });
        }
        Ok((
            entry,
            StructureId::ChunkEntry,
            self.inode_provenance(
                Span {
                    offset: base,
                    len: 2,
                },
                format,
                inode,
            ),
            Some(unit),
        ))
    }

    fn locate_xattr_header(&self, inode: u64) -> Result<LocatedObject, LocateError<R::Error>> {
        let (base, end, _, xattr_size) = self.inode_tail(inode)?;
        if xattr_size == 0 {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::XattrHeader { inode },
                reason: "inode has no inline xattr region",
            });
        }
        let offset = end.checked_sub(xattr_size).ok_or(LocateError::Overflow)?;
        Ok((
            offset,
            StructureId::XattrHeader,
            self.inode_provenance(
                Span {
                    offset: base,
                    len: 2,
                },
                self.read_u16(base)?,
                inode,
            ),
            None,
        ))
    }

    fn locate_shared_xattr_id(
        &self,
        inode: u64,
        index: u32,
    ) -> Result<LocatedObject, LocateError<R::Error>> {
        let (header, _, provenance, _) = self.locate_xattr_header(inode)?;
        let (_, _, _, xattr_size) = self.inode_tail(inode)?;
        let count = u32::from(self.read_u8(header + 4)?);
        if 12 + u64::from(count) * 4 > xattr_size {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::SharedXattrId { inode, index },
                reason: "shared xattr array exceeds inline region",
            });
        }
        if index >= count {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::SharedXattrId { inode, index },
                reason: "shared xattr index is outside h_shared_count",
            });
        }
        let base = header
            .checked_add(12 + u64::from(index) * 4)
            .ok_or(LocateError::Overflow)?;
        Ok((base, StructureId::SharedXattrId, provenance, None))
    }

    fn locate_inline_xattr(
        &self,
        inode: u64,
        index: u32,
    ) -> Result<LocatedObject, LocateError<R::Error>> {
        let (inode_base, tail, _, xattr_size) = self.inode_tail(inode)?;
        if xattr_size == 0 {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::InlineXattr { inode, index },
                reason: "inode has no inline xattr region",
            });
        }
        let header = tail - xattr_size;
        let shared = u64::from(self.read_u8(header + 4)?);
        if 12 + shared * 4 > xattr_size {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::InlineXattr { inode, index },
                reason: "shared xattr array exceeds inline region",
            });
        }
        let mut pos = header + 12 + shared * 4;
        for _ in 0..index {
            if pos + 4 > tail {
                return Err(LocateError::UnresolvedParent {
                    object: ObjectRef::InlineXattr { inode, index },
                    reason: "xattr index exceeds inline region",
                });
            }
            let size = 4 + u64::from(self.read_u8(pos)?) + u64::from(self.read_u16(pos + 2)?);
            pos = align_up(pos.checked_add(size).ok_or(LocateError::Overflow)?, 4)?;
        }
        if pos + 4 > tail {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::InlineXattr { inode, index },
                reason: "xattr entry header exceeds inline region",
            });
        }
        let size = align_up(
            4 + u64::from(self.read_u8(pos)?) + u64::from(self.read_u16(pos + 2)?),
            4,
        )?;
        if pos + size > tail {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::InlineXattr { inode, index },
                reason: "xattr entry exceeds inline region",
            });
        }
        Ok((
            pos,
            StructureId::XattrEntry,
            self.inode_provenance(
                Span {
                    offset: inode_base,
                    len: 2,
                },
                self.read_u16(inode_base)?,
                inode,
            ),
            Some(size),
        ))
    }

    fn locate_xattr_prefix(&self, index: u8) -> Result<LocatedObject, LocateError<R::Error>> {
        if index >= self.superblock.xattr_prefix_count {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::XattrLongPrefix { index },
                reason: "prefix index is outside xattr_prefix_count",
            });
        }
        if self.superblock.feature_incompat & FEATURE_INCOMPAT_XATTR_PREFIXES == 0 {
            return Err(LocateError::AbsentByFeature {
                field: "erofs.xattr.prefix.length",
                predicate: Predicate::WithXattrPrefixes,
            });
        }
        let mut pos = u64::from(self.superblock.xattr_prefix_start)
            .checked_mul(4)
            .ok_or(LocateError::Overflow)?;
        for _ in 0..index {
            let len = metadata_length(self.read_u16(pos)?);
            pos = align_up(pos.checked_add(2 + len).ok_or(LocateError::Overflow)?, 4)?;
        }
        let len = metadata_length(self.read_u16(pos)?);
        // A zero length word decodes to 65536 and is rejected by the > 256
        // bound, so no explicit zero-length arm is needed here.
        if len > 256 {
            return Err(LocateError::InvalidStructure {
                object: ObjectRef::XattrLongPrefix { index },
                reason: "invalid long-prefix payload length",
            });
        }
        Ok((pos, StructureId::XattrLongPrefix, [None; 6], Some(len)))
    }

    fn locate_compression_config(
        &self,
        algorithm: u8,
    ) -> Result<LocatedObject, LocateError<R::Error>> {
        if self.superblock.feature_incompat & FEATURE_INCOMPAT_COMPR_CFGS == 0 {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::CompressionConfig { algorithm },
                reason: "compression configuration feature is disabled",
            });
        }
        if algorithm >= 4 {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::CompressionConfig { algorithm },
                reason: "unknown compression algorithm",
            });
        }
        let bitmap = self.read_u16(SUPERBLOCK_OFFSET + 84)?;
        if bitmap & (1 << algorithm) == 0 {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::CompressionConfig { algorithm },
                reason: "algorithm is absent from available_compr_algs",
            });
        }
        let mut pos = SUPERBLOCK_OFFSET
            + SUPERBLOCK_BASE_SIZE
            + u64::from(self.superblock.ext_slots) * SUPERBLOCK_EXTSLOT_SIZE;
        for id in 0..algorithm {
            if bitmap & (1 << id) != 0 {
                let len = metadata_length(self.read_u16(pos)?);
                pos = align_up(pos.checked_add(2 + len).ok_or(LocateError::Overflow)?, 4)?;
            }
        }
        let len = metadata_length(self.read_u16(pos)?);
        Ok((pos, StructureId::CompressionConfig, [None; 6], Some(len)))
    }

    fn locate_compression_map(&self, inode: u64) -> Result<LocatedObject, LocateError<R::Error>> {
        let (base, end, format, _) = self.inode_tail(inode)?;
        let layout = (format & INODE_LAYOUT_MASK) >> INODE_LAYOUT_SHIFT;
        if layout != LAYOUT_COMPRESSED_FULL && layout != LAYOUT_COMPRESSED_COMPACT {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::CompressionMap { inode },
                reason: "inode is not compressed",
            });
        }
        Ok((
            align_up(end, 8)?,
            StructureId::CompressionMap,
            self.inode_provenance(
                Span {
                    offset: base,
                    len: 2,
                },
                format,
                inode,
            ),
            None,
        ))
    }

    fn locate_compression_index(
        &self,
        inode: u64,
        index: u64,
    ) -> Result<LocatedObject, LocateError<R::Error>> {
        let (map, _, provenance, _) = self.locate_compression_map(inode)?;
        let base = map
            .checked_add(16)
            .and_then(|v| v.checked_add(index.checked_mul(8)?))
            .ok_or(LocateError::Overflow)?;
        Ok((base, StructureId::CompressionIndex, provenance, None))
    }

    fn locate_compact_pack(
        &self,
        inode: u64,
        index: u64,
    ) -> Result<LocatedObject, LocateError<R::Error>> {
        let (map, _, provenance, _) = self.locate_compression_map(inode)?;
        let unit = if self.read_u16(map + 4)? & 1 != 0 {
            32
        } else {
            8
        };
        let start = align_up(map + 8, 8)?;
        let base = start
            .checked_add(index.checked_mul(unit).ok_or(LocateError::Overflow)?)
            .ok_or(LocateError::Overflow)?;
        Ok((
            base,
            StructureId::CompressionCompactPack,
            provenance,
            Some(unit),
        ))
    }

    fn locate_compression_extent(
        &self,
        inode: u64,
        index: u64,
    ) -> Result<LocatedObject, LocateError<R::Error>> {
        let (map, _, provenance, _) = self.locate_compression_map(inode)?;
        let advise = self.read_u16(map + 4)?;
        if advise & ADVISE_EXTENTS == 0 {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::CompressionExtent { inode, index },
                reason: "compressed inode does not use extents",
            });
        }
        let unit = 4_u64 << ((advise >> 1) & 3);
        let mut start = align_up(map + 8, unit)?;
        if unit == 4 {
            start = start.checked_add(8).ok_or(LocateError::Overflow)?;
        }
        let base = start
            .checked_add(index.checked_mul(unit).ok_or(LocateError::Overflow)?)
            .ok_or(LocateError::Overflow)?;
        Ok((base, StructureId::CompressionExtent, provenance, Some(unit)))
    }

    fn dynamic_field_len(
        &self,
        base: u64,
        field: &FieldDef,
        object_len: Option<u64>,
    ) -> Result<u64, LocateError<R::Error>> {
        if field.storage.len != 0 {
            return Ok(field.storage.len);
        }
        let len = match field.id {
            "erofs.xattr.entry.name" => u64::from(self.read_u8(base)?),
            "erofs.xattr.entry.value" => u64::from(self.read_u16(base + 2)?),
            "erofs.xattr.prefix.infix" => object_len.unwrap_or(0).saturating_sub(1),
            "erofs.compression.config.payload" => object_len.unwrap_or(0),
            "erofs.compression.compact_pack.raw" => object_len.unwrap_or(0),
            _ => object_len.unwrap_or(0),
        };
        if len > 64 {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::Superblock,
                reason: "variable field exceeds bounded occurrence buffer",
            });
        }
        Ok(len)
    }
    fn locate_dirent(
        &self,
        directory: u64,
        block: u64,
        index: u32,
    ) -> Result<LocatedObject, LocateError<R::Error>> {
        let (inode_offset, inode_structure, inode_provenance, _) =
            self.locate_inode(MetadataSpace::Primary, directory)?;
        let format = inode_provenance[3].unwrap().value as u16;
        let layout = (format & INODE_LAYOUT_MASK) >> INODE_LAYOUT_SHIFT;
        let inode_size = if inode_structure == StructureId::CompactInode {
            COMPACT_INODE_SIZE
        } else {
            EXTENDED_INODE_SIZE
        };
        let size = if inode_structure == StructureId::CompactInode {
            u64::from(self.read_u32(inode_offset + 8)?)
        } else {
            self.read_u64(inode_offset + 8)?
        };
        let mode = self.read_u16(inode_offset + 4)?;
        if self.mode == ParseMode::Strict && mode & MODE_TYPE_MASK != MODE_DIRECTORY {
            return Err(LocateError::InvalidStructure {
                object: ObjectRef::Dirent {
                    directory,
                    block,
                    index,
                },
                reason: "dirent parent is not a directory inode",
            });
        }
        let xattr_count = u64::from(self.read_u16(inode_offset + 2)?);
        let xattr_size = if xattr_count == 0 {
            0
        } else {
            12 + (xattr_count - 1) * 4
        };
        let block_size = 1_u64
            .checked_shl(u32::from(self.superblock.blkszbits))
            .ok_or(LocateError::Overflow)?;
        let block_start = block.checked_mul(block_size).ok_or(LocateError::Overflow)?;
        if block_start >= size {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::Dirent {
                    directory,
                    block,
                    index,
                },
                reason: "directory block is beyond inode size",
            });
        }
        let tail_size = size % block_size;
        let last_block = (size - 1) / block_size;
        let data_base = match layout {
            LAYOUT_FLAT_PLAIN => {
                let startblk = u64::from(self.read_u32(inode_offset + 16)?);
                startblk
                    .checked_mul(block_size)
                    .and_then(|base| base.checked_add(block_start))
                    .ok_or(LocateError::Overflow)?
            }
            LAYOUT_FLAT_INLINE if tail_size != 0 && block == last_block => inode_offset
                .checked_add(inode_size)
                .and_then(|base| base.checked_add(xattr_size))
                .ok_or(LocateError::Overflow)?,
            LAYOUT_FLAT_INLINE => {
                let startblk = u64::from(self.read_u32(inode_offset + 16)?);
                startblk
                    .checked_mul(block_size)
                    .and_then(|base| base.checked_add(block_start))
                    .ok_or(LocateError::Overflow)?
            }
            1 | 3 => {
                return Err(LocateError::UnsupportedCapability(
                    Capability::CompressedDirectory,
                ));
            }
            4 => {
                return Err(LocateError::UnsupportedCapability(
                    Capability::ChunkDirectory,
                ));
            }
            _ => {
                return Err(LocateError::UnresolvedParent {
                    object: ObjectRef::Dirent {
                        directory,
                        block,
                        index,
                    },
                    reason: "unknown directory data layout",
                });
            }
        };
        let relative = u64::from(index)
            .checked_mul(DIRENT_SIZE)
            .ok_or(LocateError::Overflow)?;
        let available = if block == last_block && tail_size != 0 {
            tail_size
        } else {
            block_size
        };
        let dirent_end = relative
            .checked_add(DIRENT_SIZE)
            .ok_or(LocateError::Overflow)?;
        if dirent_end > available {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::Dirent {
                    directory,
                    block,
                    index,
                },
                reason: "dirent index is outside the directory block",
            });
        }
        let offset = data_base
            .checked_add(relative)
            .ok_or(LocateError::Overflow)?;
        ensure_span::<R::Error>(
            Span::new(offset, DIRENT_SIZE).map_err(|_| LocateError::Overflow)?,
            self.image.len(),
        )?;
        let first_nameoff_offset = data_base.checked_add(8).ok_or(LocateError::Overflow)?;
        ensure_span::<R::Error>(
            Span::new(first_nameoff_offset, 2).map_err(|_| LocateError::Overflow)?,
            self.image.len(),
        )?;
        let first_nameoff = u64::from(self.read_u16(first_nameoff_offset)?);
        if first_nameoff == 0 || first_nameoff >= available || first_nameoff % DIRENT_SIZE != 0 {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::Dirent {
                    directory,
                    block,
                    index,
                },
                reason: "first dirent nameoff does not define an unambiguous header array",
            });
        }
        if u64::from(index) >= first_nameoff / DIRENT_SIZE {
            return Err(LocateError::UnresolvedParent {
                object: ObjectRef::Dirent {
                    directory,
                    block,
                    index,
                },
                reason: "dirent index is outside the declared header array",
            });
        }
        Ok((offset, StructureId::Dirent, inode_provenance, None))
    }

    fn inode_provenance(
        &self,
        format_span: Span,
        format: u16,
        nid: u64,
    ) -> [Option<DependencyRead>; 6] {
        [
            Some(DependencyRead {
                field: "erofs.superblock.blkszbits",
                span: Span {
                    offset: SUPERBLOCK_OFFSET + 12,
                    len: 1,
                },
                value: u64::from(self.superblock.blkszbits),
            }),
            Some(DependencyRead {
                field: "erofs.superblock.meta_blkaddr",
                span: Span {
                    offset: SUPERBLOCK_OFFSET + 40,
                    len: 4,
                },
                value: u64::from(self.superblock.meta_blkaddr),
            }),
            Some(DependencyRead {
                field: "erofs.object.inode.nid",
                span: Span { offset: 0, len: 0 },
                value: nid,
            }),
            Some(DependencyRead {
                field: "erofs.inode.i_format",
                span: format_span,
                value: u64::from(format),
            }),
            None,
            None,
        ]
    }

    fn read_u8(&self, offset: u64) -> Result<u8, LocateError<R::Error>> {
        let mut raw = [0; 1];
        self.image
            .read_exact_at(offset, &mut raw)
            .map_err(LocateError::Read)?;
        Ok(raw[0])
    }
    fn read_u16(&self, offset: u64) -> Result<u16, LocateError<R::Error>> {
        let mut raw = [0; 2];
        self.image
            .read_exact_at(offset, &mut raw)
            .map_err(LocateError::Read)?;
        Ok(le_u16(raw))
    }

    fn read_u32(&self, offset: u64) -> Result<u32, LocateError<R::Error>> {
        let mut raw = [0; 4];
        self.image
            .read_exact_at(offset, &mut raw)
            .map_err(LocateError::Read)?;
        Ok(le_u32(raw))
    }

    fn read_u64(&self, offset: u64) -> Result<u64, LocateError<R::Error>> {
        let mut raw = [0; 8];
        self.image
            .read_exact_at(offset, &mut raw)
            .map_err(LocateError::Read)?;
        Ok(le_u64(raw))
    }
}

fn decode(encoding: Encoding, raw: [u8; 64], len: u8) -> DecodedValue {
    match encoding {
        Encoding::U8 => DecodedValue::Unsigned(u64::from(raw[0])),
        Encoding::LeU16 => DecodedValue::Unsigned(u64::from(le_u16(raw[..2].try_into().unwrap()))),
        Encoding::LeU32 => DecodedValue::Unsigned(u64::from(le_u32(raw[..4].try_into().unwrap()))),
        Encoding::LeU64 => DecodedValue::Unsigned(le_u64(raw[..8].try_into().unwrap())),
        Encoding::Bytes => DecodedValue::Bytes { bytes: raw, len },
    }
}

fn align_up<E>(value: u64, alignment: u64) -> Result<u64, LocateError<E>> {
    value
        .checked_add(alignment - 1)
        .map(|v| v / alignment * alignment)
        .ok_or(LocateError::Overflow)
}

fn metadata_length(raw: u16) -> u64 {
    if raw == 0 { 65_536 } else { u64::from(raw) }
}

fn ensure_span<E>(span: Span, image_len: u64) -> Result<(), LocateError<E>> {
    if span.is_within(image_len) {
        Ok(())
    } else {
        Err(LocateError::OutOfBounds { span, image_len })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        SUPERBLOCK_MAGIC, SliceReader,
        schema::{FIELDS, Predicate, StructureId, field_by_id},
    };

    fn image() -> [u8; 16 * 1024] {
        let mut image = [0; 16 * 1024];
        image[1024..1028].copy_from_slice(&SUPERBLOCK_MAGIC.to_le_bytes());
        image[1036] = 12;
        image[1037] = 1;
        image[1064..1068].copy_from_slice(&1_u32.to_le_bytes());
        image
    }

    #[test]
    fn locates_superblock_union_views_by_feature() {
        let image = image();
        let reader = SliceReader::new(&image);
        let locator = Locator::new(&reader).unwrap();
        let root = locator
            .locate(
                ObjectRef::Superblock,
                field_by_id("erofs.superblock.rootnid_2b").unwrap(),
            )
            .unwrap();
        assert_eq!(
            root.span,
            Span {
                offset: 1038,
                len: 2
            }
        );
        assert!(matches!(
            locator.locate(
                ObjectRef::Superblock,
                field_by_id("erofs.superblock.blocks_hi").unwrap()
            ),
            Err(LocateError::AbsentByFeature { .. })
        ));
    }

    #[test]
    fn locates_compact_and_extended_inode_fields() {
        let mut image = image();
        let compact = 4096 + 3 * 32;
        image[compact..compact + 2].copy_from_slice(&0_u16.to_le_bytes());
        image[compact + 8..compact + 12].copy_from_slice(&123_u32.to_le_bytes());
        let extended = 4096 + 5 * 32;
        image[extended..extended + 2].copy_from_slice(&1_u16.to_le_bytes());
        image[extended + 8..extended + 16].copy_from_slice(&456_u64.to_le_bytes());
        let reader = SliceReader::new(&image);
        let locator = Locator::new(&reader).unwrap();

        let compact_size = locator
            .locate(
                ObjectRef::Inode {
                    space: MetadataSpace::Primary,
                    nid: 3,
                },
                field_by_id("erofs.inode.compact.i_size").unwrap(),
            )
            .unwrap();
        assert_eq!(compact_size.value, DecodedValue::Unsigned(123));
        assert_eq!(compact_size.provenance[2].unwrap().value, 3);

        let extended_size = locator
            .locate(
                ObjectRef::Inode {
                    space: MetadataSpace::Primary,
                    nid: 5,
                },
                field_by_id("erofs.inode.extended.i_size").unwrap(),
            )
            .unwrap();
        assert_eq!(extended_size.value, DecodedValue::Unsigned(456));
    }

    #[test]
    fn locates_flat_plain_dirent() {
        let mut image = image();
        let inode = 4096 + 3 * 32;
        image[inode..inode + 2].copy_from_slice(&0_u16.to_le_bytes());
        image[inode + 4..inode + 6].copy_from_slice(&MODE_DIRECTORY.to_le_bytes());
        image[inode + 8..inode + 12].copy_from_slice(&4096_u32.to_le_bytes());
        image[inode + 16..inode + 20].copy_from_slice(&2_u32.to_le_bytes());
        image[8200..8202].copy_from_slice(&24_u16.to_le_bytes());
        let dirent = 8192 + 12;
        image[dirent..dirent + 8].copy_from_slice(&77_u64.to_le_bytes());
        let reader = SliceReader::new(&image);
        let locator = Locator::new(&reader).unwrap();

        let nid = locator
            .locate(
                ObjectRef::Dirent {
                    directory: 3,
                    block: 0,
                    index: 1,
                },
                field_by_id("erofs.dirent.nid").unwrap(),
            )
            .unwrap();
        assert_eq!(
            nid.span,
            Span {
                offset: 8204,
                len: 8
            }
        );
        assert_eq!(nid.value, DecodedValue::Unsigned(77));
    }

    #[test]
    fn arbitrary_short_images_fail_without_panicking() {
        let bytes = [0; 1151];
        for len in 0..bytes.len() {
            let reader = SliceReader::new(&bytes[..len]);
            assert!(matches!(
                Locator::new(&reader),
                Err(LocateError::OutOfBounds { .. })
            ));
        }
    }

    #[test]
    fn rejects_overflow_and_out_of_bounds_parents() {
        let mut image = image();
        image[1036] = 63;
        image[1064..1068].copy_from_slice(&u32::MAX.to_le_bytes());
        let reader = SliceReader::new(&image);
        let locator = Locator::new(&reader).unwrap();
        assert!(matches!(
            locator.locate(
                ObjectRef::Inode {
                    space: MetadataSpace::Primary,
                    nid: u64::MAX,
                },
                field_by_id("erofs.inode.compact.i_format").unwrap()
            ),
            Err(LocateError::Overflow)
        ));
    }
    #[test]
    fn chunk_size_shift_overflow_is_checked() {
        let mut image = image();
        image[1036] = 63;
        image[1064..1068].copy_from_slice(&0_u32.to_le_bytes());
        let inode = 3 * 32;
        image[inode..inode + 2].copy_from_slice(&(LAYOUT_CHUNK << 1).to_le_bytes());
        image[inode + 16..inode + 18].copy_from_slice(&(CHUNK_FORMAT_INDEXES | 1).to_le_bytes());
        let reader = SliceReader::new(&image);
        let locator = Locator::new(&reader).unwrap();
        assert!(matches!(
            locator.locate(
                ObjectRef::Chunk { inode: 3, index: 0 },
                field_by_id("erofs.chunk.device_id").unwrap()
            ),
            Err(LocateError::Overflow)
        ));
    }

    #[test]
    fn shared_xattr_array_is_bounded_by_inline_region() {
        let mut image = image();
        let inode = 4096 + 3 * 32;
        image[inode..inode + 2].copy_from_slice(&0_u16.to_le_bytes());
        image[inode + 2..inode + 4].copy_from_slice(&1_u16.to_le_bytes());
        let header = inode + 32;
        image[header + 4] = 1;
        let reader = SliceReader::new(&image);
        let locator = Locator::new(&reader).unwrap();
        assert!(matches!(
            locator.locate(
                ObjectRef::SharedXattrId { inode: 3, index: 0 },
                field_by_id("erofs.xattr.shared_id").unwrap()
            ),
            Err(LocateError::UnresolvedParent { .. })
        ));
    }

    #[test]
    fn xattr_prefix_requires_incompat_feature() {
        let mut image = image();
        image[1032..1036].copy_from_slice(&0x10_u32.to_le_bytes());
        image[1115] = 1;
        image[1116..1120].copy_from_slice(&800_u32.to_le_bytes());
        let reader = SliceReader::new(&image);
        let locator = Locator::new(&reader).unwrap();
        assert!(matches!(
            locator.locate(
                ObjectRef::XattrLongPrefix { index: 0 },
                field_by_id("erofs.xattr.prefix.length").unwrap()
            ),
            Err(LocateError::AbsentByFeature { .. })
        ));
    }

    #[test]
    fn locates_chunk_index_device_and_48bit_fields() {
        let mut image = image();
        image[1104..1108].copy_from_slice(
            &(FEATURE_INCOMPAT_48BIT | FEATURE_INCOMPAT_DEVICE_TABLE).to_le_bytes(),
        );
        image[1110..1112].copy_from_slice(&1_u16.to_le_bytes());
        image[1112..1114].copy_from_slice(&96_u16.to_le_bytes());
        let device = 96 * 128;
        image[device + 74..device + 76].copy_from_slice(&2_u16.to_le_bytes());
        let inode = 4096 + 3 * 32;
        image[inode..inode + 2].copy_from_slice(&(LAYOUT_CHUNK << 1).to_le_bytes());
        image[inode + 8..inode + 12].copy_from_slice(&4096_u32.to_le_bytes());
        image[inode + 16..inode + 18].copy_from_slice(&CHUNK_FORMAT_INDEXES.to_le_bytes());
        image[inode + 34..inode + 36].copy_from_slice(&7_u16.to_le_bytes());
        let reader = SliceReader::new(&image);
        let locator = Locator::new(&reader).unwrap();
        let chunk = locator
            .locate(
                ObjectRef::Chunk { inode: 3, index: 0 },
                field_by_id("erofs.chunk.device_id").unwrap(),
            )
            .unwrap();
        assert_eq!(chunk.value, DecodedValue::Unsigned(7));
        let high = locator
            .locate(
                ObjectRef::DeviceSlot { index: 0 },
                field_by_id("erofs.device.uniaddr_hi").unwrap(),
            )
            .unwrap();
        assert_eq!(high.value, DecodedValue::Unsigned(2));
    }

    #[test]
    fn locates_inline_xattr_and_compression_metadata() {
        let mut image = image();
        let inode = 4096 + 3 * 32;
        image[inode..inode + 2].copy_from_slice(&(LAYOUT_COMPRESSED_FULL << 1).to_le_bytes());
        image[inode + 2..inode + 4].copy_from_slice(&5_u16.to_le_bytes());
        let header = inode + 32;
        image[header + 4] = 1;
        image[header + 12..header + 16].copy_from_slice(&9_u32.to_le_bytes());
        image[header + 16] = 1;
        image[header + 17] = 6;
        image[header + 18..header + 20].copy_from_slice(&3_u16.to_le_bytes());
        let map = 4256;
        image[map + 4..map + 6].copy_from_slice(&0_u16.to_le_bytes());
        image[map + 6] = 0x10;
        let reader = SliceReader::new(&image);
        let locator = Locator::new(&reader).unwrap();
        let shared = locator
            .locate(
                ObjectRef::SharedXattrId { inode: 3, index: 0 },
                field_by_id("erofs.xattr.shared_id").unwrap(),
            )
            .unwrap();
        assert_eq!(shared.value, DecodedValue::Unsigned(9));
        let entry = locator
            .locate(
                ObjectRef::InlineXattr { inode: 3, index: 0 },
                field_by_id("erofs.xattr.entry.value_size").unwrap(),
            )
            .unwrap();
        assert_eq!(entry.value, DecodedValue::Unsigned(3));
        let algorithm = locator
            .locate(
                ObjectRef::CompressionMap { inode: 3 },
                field_by_id("erofs.compression.map.algorithmtype").unwrap(),
            )
            .unwrap();
        assert_eq!(algorithm.value, DecodedValue::Unsigned(0x10));
    }

    #[test]
    fn locates_plain_long_prefix_and_metabox_inode() {
        let mut image = image();
        image[1032..1036].copy_from_slice(&0x10_u32.to_le_bytes());
        image[1104..1108].copy_from_slice(
            &(FEATURE_INCOMPAT_XATTR_PREFIXES | FEATURE_INCOMPAT_METABOX).to_le_bytes(),
        );
        image[1115] = 1;
        image[1116..1120].copy_from_slice(&800_u32.to_le_bytes());
        image[3200..3202].copy_from_slice(&3_u16.to_le_bytes());
        image[3202] = 1;
        image[3203..3205].copy_from_slice(b"ab");
        image[64..66].copy_from_slice(&0_u16.to_le_bytes());
        let reader = SliceReader::new(&image);
        let locator = Locator::new(&reader).unwrap();
        let infix = locator
            .locate(
                ObjectRef::XattrLongPrefix { index: 0 },
                field_by_id("erofs.xattr.prefix.infix").unwrap(),
            )
            .unwrap();
        assert_eq!(&infix.raw[..2], b"ab");
        let inode = locator
            .locate(
                ObjectRef::Inode {
                    space: MetadataSpace::Metabox,
                    nid: 2,
                },
                field_by_id("erofs.inode.compact.i_format").unwrap(),
            )
            .unwrap();
        assert_eq!(inode.span.offset, 64);
    }
    #[test]
    fn locates_every_superblock_field_across_feature_views() {
        let mut plain = image();
        plain[1037] = 1;
        let mut with_48bit = plain;
        with_48bit[1104..1108].copy_from_slice(&FEATURE_INCOMPAT_48BIT.to_le_bytes());
        let mut with_compression = plain;
        with_compression[1104..1108].copy_from_slice(&FEATURE_INCOMPAT_COMPR_CFGS.to_le_bytes());

        let plain_reader = SliceReader::new(&plain);
        let bit48_reader = SliceReader::new(&with_48bit);
        let compression_reader = SliceReader::new(&with_compression);
        let locators = [
            Locator::new(&plain_reader).unwrap(),
            Locator::new(&bit48_reader).unwrap(),
            Locator::new(&compression_reader).unwrap(),
        ];

        for field in FIELDS
            .iter()
            .filter(|field| field.structure == StructureId::Superblock)
        {
            let located = locators
                .iter()
                .any(|locator| locator.locate(ObjectRef::Superblock, field).is_ok());
            assert!(located, "{} ({:?})", field.id, field.presence);
            assert!(matches!(
                field.presence,
                Predicate::Always
                    | Predicate::Without48Bit
                    | Predicate::With48Bit
                    | Predicate::WithoutCompressionConfig
                    | Predicate::WithCompressionConfig
                    | Predicate::Superblock144
            ));
        }
    }
}
