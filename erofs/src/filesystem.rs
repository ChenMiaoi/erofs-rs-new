use std::{format, string::ToString};

use binrw::BinRead;
use binrw::BinReaderExt;
use binrw::io::Cursor;

use crate::types::*;
use crate::{Error, Result};

const ALL_INCOMPAT_FEATURES: u32 = 0x0000_01ff;
const SUPPORTED_INCOMPAT_FEATURES: u32 = 0x0000_0005;

/// Shared core data and pure computation logic for EROFS filesystem.
///
/// This struct is used by both sync and async `EroFS` implementations
/// to avoid duplicating parsing and calculation logic.
#[derive(Debug, Clone)]
pub struct EroFSCore {
    pub(crate) super_block: SuperBlock,
    pub(crate) block_size: usize,
}

/// Describes a planned block read operation.
///
/// Used by both sync and async implementations to share the layout
/// calculation logic, while keeping the actual I/O separate.
pub enum BlockPlan {
    /// A direct read: read `size` bytes at `offset`.
    Direct { offset: usize, size: usize },
    /// A two-phase read for chunk-based layout:
    /// 1. Read 4 bytes at `addr_offset` to get chunk address
    /// 2. Call `resolve_chunk_read()` with the chunk address
    Chunked {
        addr_offset: usize,
        chunk_fixed: usize,
        chunk_size: usize,
        data_size: usize,
        chunk_index: usize,
    },
}

impl EroFSCore {
    /// Parse and validate a superblock from raw bytes.
    ///
    /// `data` should be the bytes starting at `SUPER_BLOCK_OFFSET`.
    pub(crate) fn new(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        let super_block = SuperBlock::read(&mut cursor)?;

        let magic_number = super_block.magic;
        let blk_size_bits = super_block.blk_size_bits;

        if magic_number != MAGIC_NUMBER {
            return Err(Error::InvalidSuperblock(format!(
                "invalid magic number: 0x{:x}",
                magic_number
            )));
        }

        let unknown_features = super_block.feature_incompat & !ALL_INCOMPAT_FEATURES;
        if unknown_features != 0 {
            return Err(Error::InvalidSuperblock(format!(
                "unknown incompatible feature bits: 0x{unknown_features:08x}"
            )));
        }

        let unsupported_features = super_block.feature_incompat & !SUPPORTED_INCOMPAT_FEATURES;
        if unsupported_features != 0 {
            return Err(Error::NotSupported(format!(
                "incompatible feature bits: 0x{unsupported_features:08x}"
            )));
        }

        if !(9..=24).contains(&blk_size_bits) {
            return Err(Error::InvalidSuperblock(format!(
                "invalid block size bits: {}",
                blk_size_bits
            )));
        }

        let block_size = 1_usize
            .checked_shl(u32::from(blk_size_bits))
            .ok_or_else(|| {
                Error::InvalidSuperblock("block size exceeds platform limits".to_string())
            })?;
        Ok(Self {
            super_block,
            block_size,
        })
    }

    /// Parse an inode from raw bytes.
    pub(crate) fn parse_inode(&self, data: &[u8], nid: u64) -> Result<Inode> {
        let mut inode_buf = Cursor::new(data);
        let layout: u16 = inode_buf.read_le()?;
        inode_buf.set_position(0);
        if Inode::is_compact_format(layout) {
            let inode = InodeCompact::read(&mut inode_buf)?;
            Ok(Inode::Compact((nid, inode)))
        } else {
            let inode = InodeExtended::read(&mut inode_buf)?;
            Ok(Inode::Extended((nid, inode)))
        }
    }

    /// Plan a block read operation for the given inode and offset.
    ///
    /// Returns a `BlockPlan` describing what bytes to read.
    /// For `BlockPlan::Chunked`, the caller must perform an additional
    /// read and call `resolve_chunk_read()`.
    pub(crate) fn plan_inode_block_read(&self, inode: &Inode, offset: usize) -> Result<BlockPlan> {
        match inode.layout()? {
            Layout::FlatPlain => {
                let data_size = inode.data_size_checked()?;
                let block_count = data_size.div_ceil(self.block_size);
                let block_index = offset / self.block_size;
                if block_index >= block_count {
                    return Err(Error::OutOfRange(block_index, block_count));
                }

                let file_offset = block_index.checked_mul(self.block_size).ok_or_else(|| {
                    Error::CorruptedData("file block offset overflow".to_string())
                })?;
                let size = (data_size - file_offset).min(self.block_size);
                let offset = self
                    .block_offset(inode.raw_block_addr())?
                    .checked_add(file_offset)
                    .ok_or_else(|| Error::CorruptedData("data offset overflow".to_string()))?;
                Ok(BlockPlan::Direct { offset, size })
            }
            Layout::FlatInline => {
                let data_size = inode.data_size_checked()?;
                let block_count = data_size.div_ceil(self.block_size);
                let block_index = offset / self.block_size;
                if block_index >= block_count {
                    return Err(Error::OutOfRange(block_index, block_count));
                }

                let tail_size = data_size % self.block_size;
                if tail_size != 0 && block_index == block_count - 1 {
                    let offset = self
                        .get_inode_offset(inode.id())?
                        .checked_add(inode.size())
                        .and_then(|offset| offset.checked_add(inode.xattr_size()))
                        .ok_or_else(|| {
                            Error::CorruptedData("inline data offset overflow".to_string())
                        })?;
                    return Ok(BlockPlan::Direct {
                        offset,
                        size: tail_size,
                    });
                }

                let file_offset = block_index.checked_mul(self.block_size).ok_or_else(|| {
                    Error::CorruptedData("file block offset overflow".to_string())
                })?;
                let offset = self
                    .block_offset(inode.raw_block_addr())?
                    .checked_add(file_offset)
                    .ok_or_else(|| Error::CorruptedData("data offset overflow".to_string()))?;
                let size = (data_size - file_offset).min(self.block_size);
                Ok(BlockPlan::Direct { offset, size })
            }
            Layout::CompressedFull | Layout::CompressedCompact => {
                Err(Error::NotSupported("compressed compact layout".to_string()))
            }
            Layout::ChunkBased => {
                let chunk_format = ChunkBasedFormat::new(inode.raw_block_addr());
                if !chunk_format.is_valid() {
                    return Err(Error::CorruptedData(format!(
                        "invalid chunk based format {}",
                        inode.raw_block_addr()
                    )));
                } else if chunk_format.is_indexes() {
                    return Err(Error::NotSupported(
                        "chunk based format with indexes".to_string(),
                    ));
                }

                let chunk_bits = chunk_format.chunk_size_bits() + self.super_block.blk_size_bits;
                let chunk_size = 1_usize.checked_shl(u32::from(chunk_bits)).ok_or_else(|| {
                    Error::CorruptedData("chunk size exceeds platform limits".to_string())
                })?;
                let data_size = inode.data_size_checked()?;
                let chunk_count = data_size.div_ceil(chunk_size);
                let chunk_index = offset / chunk_size;
                let chunk_fixed = offset % chunk_size / self.block_size;
                if chunk_index >= chunk_count {
                    return Err(Error::OutOfRange(chunk_index, chunk_count));
                }

                let chunk_table_offset = chunk_index.checked_mul(4).ok_or_else(|| {
                    Error::CorruptedData("chunk index offset overflow".to_string())
                })?;
                let addr_offset = self
                    .get_inode_offset(inode.id())?
                    .checked_add(inode.size())
                    .and_then(|offset| offset.checked_add(inode.xattr_size()))
                    .and_then(|offset| offset.checked_add(chunk_table_offset))
                    .ok_or_else(|| {
                        Error::CorruptedData("chunk address offset overflow".to_string())
                    })?;

                Ok(BlockPlan::Chunked {
                    addr_offset,
                    chunk_fixed,
                    chunk_size,
                    data_size,
                    chunk_index,
                })
            }
        }
    }

    /// Resolve the final read offset and size for a chunk-based block read.
    ///
    /// `chunk_addr` is the i32 value read from `addr_offset` in the `Chunked` plan.
    /// `chunk_size` is the full chunk size in bytes (may span multiple blocks).
    pub(crate) fn resolve_chunk_read(
        &self,
        chunk_addr: i32,
        chunk_fixed: usize,
        chunk_size: usize,
        data_size: usize,
        chunk_index: usize,
    ) -> Result<(usize, usize)> {
        if chunk_addr <= 0 {
            return Err(Error::CorruptedData(
                "sparse chunks are not supported".to_string(),
            ));
        }

        let file_byte_offset = chunk_index
            .checked_mul(chunk_size)
            .and_then(|offset| offset.checked_add(chunk_fixed.checked_mul(self.block_size)?))
            .ok_or_else(|| Error::CorruptedData("chunk file offset overflow".to_string()))?;
        let remaining = data_size.saturating_sub(file_byte_offset);
        let read_size = remaining.min(self.block_size);

        if read_size == 0 {
            return Err(Error::OutOfRange(file_byte_offset, data_size));
        }

        let block = u32::try_from(chunk_addr)
            .map_err(|_| Error::CorruptedData("invalid chunk address".to_string()))?
            .checked_add(
                u32::try_from(chunk_fixed)
                    .map_err(|_| Error::CorruptedData("chunk block index overflow".to_string()))?,
            )
            .ok_or_else(|| Error::CorruptedData("chunk block address overflow".to_string()))?;
        Ok((self.block_offset(block)?, read_size))
    }

    pub(crate) fn get_inode_offset(&self, nid: u64) -> Result<usize> {
        let metadata_offset = self.block_offset(self.super_block.meta_blk_addr)?;
        let inode_offset = nid
            .checked_mul(InodeCompact::size() as u64)
            .ok_or_else(|| Error::CorruptedData("inode offset overflow".to_string()))?;
        let inode_offset = usize::try_from(inode_offset).map_err(|_| {
            Error::CorruptedData("inode offset exceeds platform limits".to_string())
        })?;
        metadata_offset
            .checked_add(inode_offset)
            .ok_or_else(|| Error::CorruptedData("inode address overflow".to_string()))
    }

    pub(crate) fn block_offset(&self, block: u32) -> Result<usize> {
        // Widen before shifting so the computation cannot overflow on 32-bit.
        let offset = u64::from(block) << self.super_block.blk_size_bits;
        usize::try_from(offset)
            .map_err(|_| Error::CorruptedData("block address exceeds platform limits".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    fn make_core() -> EroFSCore {
        let super_block = SuperBlock {
            magic: MAGIC_NUMBER,
            checksum: 0,
            feature_compat: 0,
            blk_size_bits: 12,
            ext_slots: 0,
            root_nid: 0,
            inos: 0,
            build_time: 0,
            build_time_ns: 0,
            blocks: 0,
            meta_blk_addr: 0,
            xattr_blk_addr: 0,
            uuid: [0; 16],
            volume_name: [0; 16],
            feature_incompat: 0,
            compr_algs: 0,
            extra_devices: 0,
            devt_slot_off: 0,
            dir_blk_bits: 0,
            xattr_prefix_count: 0,
            xattr_prefix_start: 0,
            packed_nid: 0,
            xattr_filter_res: 0,
            reserved: [0; 23],
        };

        EroFSCore {
            super_block,
            block_size: 1usize << super_block.blk_size_bits,
        }
    }

    fn superblock_bytes(feature_incompat: u32) -> [u8; SuperBlock::size()] {
        let mut bytes = [0; SuperBlock::size()];
        bytes[..4].copy_from_slice(&MAGIC_NUMBER.to_le_bytes());
        bytes[12] = 12;
        bytes[80..84].copy_from_slice(&feature_incompat.to_le_bytes());
        bytes
    }

    fn make_compact_inode(
        layout: Layout,
        data_size: u32,
        xattr_count: u16,
        inode_data: u32,
    ) -> Inode {
        let format = (layout as u16) << 1;
        let inode = InodeCompact {
            format,
            xattr_count,
            mode: 0,
            nlink: 0,
            size: data_size,
            reserved: 0,
            inode_data,
            inode: 0,
            uid: 0,
            gid: 0,
            reserved2: 0,
        };
        Inode::Compact((1, inode))
    }

    #[test]
    fn rejects_unknown_incompatible_features() {
        assert!(matches!(
            EroFSCore::new(&superblock_bytes(0x8000_0000)),
            Err(Error::InvalidSuperblock(message)) if message == "unknown incompatible feature bits: 0x80000000"
        ));
    }

    #[test]
    fn rejects_unsupported_incompatible_features() {
        assert!(matches!(
            EroFSCore::new(&superblock_bytes(0x0000_0080)),
            Err(Error::NotSupported(message)) if message == "incompatible feature bits: 0x00000080"
        ));
    }

    #[test]
    fn accepts_supported_incompatible_features() {
        assert!(EroFSCore::new(&superblock_bytes(0x0000_0005)).is_ok());
    }

    #[test]
    fn xattr_size_matches_icount_formula() {
        let inode = make_compact_inode(Layout::FlatInline, 0, 0, 0);
        assert_eq!(inode.xattr_size(), 0);

        let inode = make_compact_inode(Layout::FlatInline, 0, 1, 0);
        assert_eq!(inode.xattr_size(), size_of::<XattrHeader>());

        let inode = make_compact_inode(Layout::FlatInline, 0, 2, 0);
        assert_eq!(
            inode.xattr_size(),
            size_of::<XattrHeader>() + size_of::<XattrEntry>()
        );
    }

    #[test]
    fn chunk_addr_offset_calculated_correctly() {
        let core = make_core();
        let inode = make_compact_inode(Layout::ChunkBased, core.block_size as u32, 0, 0);
        let plan = core.plan_inode_block_read(&inode, 0).expect("chunk plan");

        match plan {
            BlockPlan::Chunked { addr_offset, .. } => {
                let inode_offset = core.get_inode_offset(inode.id()).unwrap();
                let expected = inode_offset + inode.size() + inode.xattr_size();
                assert_eq!(addr_offset, expected);
            }
            _ => panic!("expected chunked plan"),
        }
    }

    #[test]
    fn flat_plain_reads_one_bounded_block_at_a_time() {
        let core = make_core();
        let inode = make_compact_inode(Layout::FlatPlain, (core.block_size + 17) as u32, 0, 7);

        assert!(matches!(
            core.plan_inode_block_read(&inode, 0).unwrap(),
            BlockPlan::Direct { size, .. } if size == core.block_size
        ));
        assert!(matches!(
            core.plan_inode_block_read(&inode, core.block_size).unwrap(),
            BlockPlan::Direct { size: 17, .. }
        ));
    }

    #[test]
    fn flat_inline_exact_block_uses_data_block() {
        let core = make_core();
        let inode = make_compact_inode(Layout::FlatInline, core.block_size as u32, 0, 7);
        let data_offset = core.block_offset(7).unwrap();

        assert!(matches!(
            core.plan_inode_block_read(&inode, 0).unwrap(),
            BlockPlan::Direct { offset, size }
                if offset == data_offset && size == core.block_size
        ));
    }

    #[test]
    fn rejects_inode_address_overflow() {
        let core = make_core();

        assert!(matches!(
            core.get_inode_offset(u64::MAX),
            Err(Error::CorruptedData(message)) if message == "inode offset overflow"
        ));
    }

    #[test]
    fn rejects_chunk_block_address_overflow() {
        let core = make_core();

        assert!(matches!(
            core.resolve_chunk_read(i32::MAX, usize::MAX, 1, 1, 0),
            Err(Error::CorruptedData(message)) if message == "chunk file offset overflow"
        ));
    }
}
