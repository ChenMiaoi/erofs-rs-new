//! Bounded, tolerant location of supported EROFS field occurrences.

use crate::schema::{Encoding, FieldDef, Predicate, StructureId};
use crate::{
    ReadAt, SUPERBLOCK_BASE_SIZE, SUPERBLOCK_EXTSLOT_SIZE, SUPERBLOCK_OFFSET, Span, le_u16, le_u32,
    le_u64, primary_inode_offset,
};

const FEATURE_INCOMPAT_COMPR_CFGS: u32 = 0x0000_0002;
const FEATURE_INCOMPAT_48BIT: u32 = 0x0000_0080;
const INODE_EXTENDED_BIT: u16 = 0x0001;
const INODE_LAYOUT_MASK: u16 = 0x000e;
const INODE_LAYOUT_SHIFT: u32 = 1;
const LAYOUT_FLAT_PLAIN: u16 = 0;
const LAYOUT_FLAT_INLINE: u16 = 2;
const COMPACT_INODE_SIZE: u64 = 32;
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
}

/// Decoded field value without heap allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedValue {
    /// Unsigned scalar value.
    Unsigned(u64),
    /// Fixed bytes, with the valid prefix indicated by `len`.
    Bytes { bytes: [u8; 16], len: u8 },
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
type Provenance = [Option<DependencyRead>; 4];
type LocatedObject = (u64, StructureId, Provenance);

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
    pub raw: [u8; 16],
    /// Number of valid bytes in `raw`.
    pub raw_len: u8,
    /// Decoded field value.
    pub value: DecodedValue,
    /// Location dependency reads, packed at the start.
    pub provenance: [Option<DependencyRead>; 4],
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
        let mut prefix = [0; 84];
        image
            .read_exact_at(SUPERBLOCK_OFFSET, &mut prefix)
            .map_err(LocateError::Read)?;
        let superblock = SuperblockContext {
            magic: le_u32(prefix[..4].try_into().unwrap()),
            blkszbits: prefix[12],
            ext_slots: prefix[13],
            meta_blkaddr: le_u32(prefix[40..44].try_into().unwrap()),
            feature_incompat: le_u32(prefix[80..84].try_into().unwrap()),
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
        let (base, structure, provenance) = match object {
            ObjectRef::Superblock => (SUPERBLOCK_OFFSET, StructureId::Superblock, [None; 4]),
            ObjectRef::Inode { space, nid } => self.locate_inode(space, nid)?,
            ObjectRef::Dirent {
                directory,
                block,
                index,
            } => self.locate_dirent(directory, block, index)?,
        };
        if field.structure != structure {
            return Err(LocateError::ObjectMismatch {
                field_structure: field.structure,
                object,
            });
        }
        self.check_presence(field)?;
        let offset = base
            .checked_add(field.storage.offset)
            .ok_or(LocateError::Overflow)?;
        let span = Span::new(offset, field.storage.len).map_err(|_| LocateError::Overflow)?;
        ensure_span::<R::Error>(span, self.image.len())?;
        let raw_len = u8::try_from(field.storage.len).map_err(|_| LocateError::Overflow)?;
        let mut raw = [0; 16];
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

    fn locate_inode(
        &self,
        space: MetadataSpace,
        nid: u64,
    ) -> Result<LocatedObject, LocateError<R::Error>> {
        if space != MetadataSpace::Primary {
            return Err(LocateError::UnsupportedCapability(Capability::Metabox));
        }
        let offset =
            primary_inode_offset(self.superblock.meta_blkaddr, self.superblock.blkszbits, nid)
                .map_err(|_| LocateError::Overflow)?;
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
        ))
    }

    fn locate_dirent(
        &self,
        directory: u64,
        block: u64,
        index: u32,
    ) -> Result<LocatedObject, LocateError<R::Error>> {
        let (inode_offset, inode_structure, inode_provenance) =
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
        Ok((offset, StructureId::Dirent, inode_provenance))
    }

    fn inode_provenance(
        &self,
        format_span: Span,
        format: u16,
        nid: u64,
    ) -> [Option<DependencyRead>; 4] {
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
        ]
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

fn decode(encoding: Encoding, raw: [u8; 16], len: u8) -> DecodedValue {
    match encoding {
        Encoding::U8 => DecodedValue::Unsigned(u64::from(raw[0])),
        Encoding::LeU16 => DecodedValue::Unsigned(u64::from(le_u16(raw[..2].try_into().unwrap()))),
        Encoding::LeU32 => DecodedValue::Unsigned(u64::from(le_u32(raw[..4].try_into().unwrap()))),
        Encoding::LeU64 => DecodedValue::Unsigned(le_u64(raw[..8].try_into().unwrap())),
        Encoding::Bytes => DecodedValue::Bytes { bytes: raw, len },
    }
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
    use crate::{SUPERBLOCK_MAGIC, SliceReader, schema::field_by_id};

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
}
