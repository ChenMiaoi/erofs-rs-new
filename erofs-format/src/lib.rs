//! Low-level primitives for decoding the EROFS on-disk format.
//!
//! This crate deliberately contains no filesystem or process I/O. Persistent
//! image offsets use `u64`, and every address calculation is checked before a
//! caller converts it to a platform-sized buffer index.

#![no_std]
#![forbid(unsafe_code)]

use core::fmt;
pub mod locator;
pub mod schema;

/// EROFS superblock magic in host byte order.
pub const SUPERBLOCK_MAGIC: u32 = 0xe0f5_e1e2;
/// Absolute byte offset of the EROFS superblock.
pub const SUPERBLOCK_OFFSET: u64 = 1024;
/// Size of the backwards-compatible superblock area.
pub const SUPERBLOCK_BASE_SIZE: u64 = 128;
/// Size of one superblock extension slot.
pub const SUPERBLOCK_EXTSLOT_SIZE: u64 = 16;
/// Size of one compact-inode slot.
pub const INODE_SLOT_SIZE: u64 = 32;

/// Chunk-format bits that encode the chunk-size shift.
pub const CHUNK_FORMAT_BLKBITS_MASK: u16 = 0x001f;
/// Selects 8-byte chunk indexes instead of 4-byte block addresses.
pub const CHUNK_FORMAT_INDEXES: u16 = 0x0020;
/// Extends a chunk address to 48 bits.
pub const CHUNK_FORMAT_48BIT: u16 = 0x0040;
/// All chunk-format bits understood by the pinned ABI.
pub const CHUNK_FORMAT_ALL: u16 = 0x007f;

/// A byte range in an image.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Span {
    /// Absolute image offset.
    pub offset: u64,
    /// Length in bytes.
    pub len: u64,
}

impl Span {
    /// Creates a span after proving that its end is representable.
    pub const fn new(offset: u64, len: u64) -> Result<Self, Error> {
        match offset.checked_add(len) {
            Some(_) => Ok(Self { offset, len }),
            None => Err(Error::Overflow),
        }
    }

    /// Returns the exclusive end offset.
    pub const fn end(self) -> Result<u64, Error> {
        match self.offset.checked_add(self.len) {
            Some(end) => Ok(end),
            None => Err(Error::Overflow),
        }
    }

    /// Returns whether this span is wholly contained in an image.
    pub const fn is_within(self, image_len: u64) -> bool {
        match self.end() {
            Ok(end) => end <= image_len,
            Err(_) => false,
        }
    }
}

/// Errors produced by checked format primitives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// An address calculation overflowed `u64`.
    Overflow,
    /// A requested span is outside the image.
    OutOfBounds { span: Span, image_len: u64 },
    /// The filesystem block-size shift cannot be represented safely.
    InvalidBlockSize(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow => f.write_str("image address calculation overflowed"),
            Self::OutOfBounds { span, image_len } => write!(
                f,
                "image span {}..{} exceeds image length {}",
                span.offset,
                span.end().unwrap_or(u64::MAX),
                image_len
            ),
            Self::InvalidBlockSize(bits) => {
                write!(f, "invalid filesystem block-size shift {bits}")
            }
        }
    }
}

impl core::error::Error for Error {}

/// Read-only random access to an image.
pub trait ReadAt {
    /// Backend-specific read failure.
    type Error: core::error::Error;

    /// Returns the image length in bytes.
    fn len(&self) -> u64;

    /// Returns whether the image is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reads an exact byte range into `dst`.
    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> Result<(), Self::Error>;
}

/// A zero-copy random-access view over an in-memory image.
#[derive(Clone, Copy, Debug)]
pub struct SliceReader<'a> {
    bytes: &'a [u8],
}

impl<'a> SliceReader<'a> {
    /// Wraps an image byte slice.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Returns an exact image span without copying.
    pub fn get(&self, span: Span) -> Result<&'a [u8], Error> {
        let end = span.end()?;
        let start = usize::try_from(span.offset).map_err(|_| Error::Overflow)?;
        let end = usize::try_from(end).map_err(|_| Error::Overflow)?;
        self.bytes
            .get(start..end)
            .ok_or_else(|| Error::OutOfBounds {
                span,
                image_len: self.len(),
            })
    }
}

impl ReadAt for SliceReader<'_> {
    type Error = Error;

    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> Result<(), Error> {
        let len = u64::try_from(dst.len()).map_err(|_| Error::Overflow)?;
        let span = Span::new(offset, len)?;
        dst.copy_from_slice(self.get(span)?);
        Ok(())
    }
}

/// Returns the byte size represented by an EROFS block-size shift.
pub const fn block_size(blkszbits: u8) -> Result<u64, Error> {
    match 1_u64.checked_shl(blkszbits as u32) {
        Some(size) => Ok(size),
        None => Err(Error::InvalidBlockSize(blkszbits)),
    }
}

/// Computes a primary-metadata inode offset using checked arithmetic.
pub const fn primary_inode_offset(
    meta_blkaddr: u32,
    blkszbits: u8,
    nid: u64,
) -> Result<u64, Error> {
    let metadata = match (meta_blkaddr as u64).checked_mul(match block_size(blkszbits) {
        Ok(size) => size,
        Err(error) => return Err(error),
    }) {
        Some(offset) => offset,
        None => return Err(Error::Overflow),
    };
    let slot = match nid.checked_mul(INODE_SLOT_SIZE) {
        Some(offset) => offset,
        None => return Err(Error::Overflow),
    };
    match metadata.checked_add(slot) {
        Some(offset) => Ok(offset),
        None => Err(Error::Overflow),
    }
}

/// Decodes a little-endian `u16`.
pub const fn le_u16(bytes: [u8; 2]) -> u16 {
    u16::from_le_bytes(bytes)
}

/// Decodes a little-endian `u32`.
pub const fn le_u32(bytes: [u8; 4]) -> u32 {
    u32::from_le_bytes(bytes)
}

/// Decodes a little-endian `u64`.
pub const fn le_u64(bytes: [u8; 8]) -> u64 {
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_rejects_overflow_and_out_of_bounds_access() {
        assert_eq!(Span::new(u64::MAX, 1), Err(Error::Overflow));

        let reader = SliceReader::new(&[1, 2, 3, 4]);
        let span = Span::new(3, 2).unwrap();
        assert_eq!(
            reader.get(span),
            Err(Error::OutOfBounds { span, image_len: 4 })
        );
    }

    #[test]
    fn slice_reader_reads_exact_spans() {
        let reader = SliceReader::new(&[1, 2, 3, 4]);
        let mut output = [0; 2];
        reader.read_exact_at(1, &mut output).unwrap();
        assert_eq!(output, [2, 3]);
    }

    #[test]
    fn primary_inode_offsets_are_checked() {
        assert_eq!(primary_inode_offset(2, 12, 3), Ok(2 * 4096 + 3 * 32));
        assert_eq!(primary_inode_offset(u32::MAX, 63, 0), Err(Error::Overflow));
        assert_eq!(primary_inode_offset(0, 12, u64::MAX), Err(Error::Overflow));
    }

    #[test]
    fn block_size_rejects_unrepresentable_shifts() {
        assert_eq!(block_size(9), Ok(512));
        assert_eq!(block_size(63), Ok(1_u64 << 63));
        assert_eq!(block_size(64), Err(Error::InvalidBlockSize(64)));
    }

    #[test]
    fn zero_length_read_at_eof_succeeds() {
        let reader = SliceReader::new(&[1, 2, 3, 4]);
        let mut output = [];
        assert_eq!(reader.read_exact_at(4, &mut output), Ok(()));
        assert_eq!(
            reader.read_exact_at(5, &mut output),
            Err(Error::OutOfBounds {
                span: Span { offset: 5, len: 0 },
                image_len: 4,
            })
        );
    }

    #[test]
    fn endian_helpers_decode_unaligned_bytes() {
        assert_eq!(le_u16([0x34, 0x12]), 0x1234);
        assert_eq!(le_u32([0x78, 0x56, 0x34, 0x12]), 0x1234_5678);
        assert_eq!(
            le_u64([0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]),
            0x0123_4567_89ab_cdef
        );
    }
}
