//! EROFS image builder: packs a host directory tree into a new image.
//!
//! The builder emits the simplest layout the kernel and this crate's reader
//! accept:
//!
//! - 4096-byte blocks, `meta_blkaddr = 0`; inode slots start right after the
//!   128-byte superblock (nid 36), matching `mkfs.erofs` images.
//! - Every inode is a 64-byte extended inode (32-bit uid/gid, 64-bit size,
//!   nanosecond mtime without superblock epoch arithmetic).
//! - File, directory, and symlink payloads use the flat plain layout with
//!   whole-block allocation. Empty files and symlinks use the null block
//!   address and own no data blocks.
//! - Directory blocks follow the canonical packing: all entries (including
//!   `.` and `..`) sorted byte-wise, dirent array first, names directly
//!   behind it, zero padding; the final block may be partially used.
//!
//! Compression, xattrs, chunk-based layout, tail-packing inline data, and
//! special files (devices, FIFOs, sockets) are intentionally unsupported.

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::types::{DirentFileType, MAGIC_NUMBER};
use crate::{Error, Result};

const BLOCK_BITS: u8 = 12;
const BLOCK_SIZE: usize = 1 << BLOCK_BITS;
const SUPERBLOCK_OFFSET: usize = erofs_format::SUPERBLOCK_OFFSET as usize;
const SUPERBLOCK_SIZE: usize = 128;
const INODE_SLOT: u64 = erofs_format::INODE_SLOT_SIZE;
/// First inode slot that does not overlap the superblock.
const FIRST_NID: u64 = (SUPERBLOCK_OFFSET as u64 + SUPERBLOCK_SIZE as u64) / INODE_SLOT;
/// Block address stored in inodes that own no data blocks (`EROFS_NULL_ADDR`).
const NULL_BLOCK_ADDR: u32 = u32::MAX;
/// `i_format`: extended inode version (bit 0) with flat plain layout (bits 1-3 = 0).
const FORMAT_EXTENDED_FLAT_PLAIN: u16 = 1;

const S_IFDIR: u16 = 0o040000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;
const PERMISSION_MASK: u32 = 0o7777;

const MAX_NAME_LEN: usize = 255;
const DIRENT_SIZE: usize = 12;

/// Builds an EROFS image from a host directory tree.
///
/// # Examples
///
/// ```no_run
/// use erofs_rs::builder::ImageBuilder;
///
/// # fn main() -> erofs_rs::Result<()> {
/// let image = ImageBuilder::new()
///     .volume_name("rootfs")?
///     .fixed_time(1_700_000_000)
///     .build_from_dir("rootfs-dir")?;
/// std::fs::write("rootfs.erofs", &image)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct ImageBuilder {
    volume_name: [u8; 16],
    uuid: [u8; 16],
    fixed_time: Option<u64>,
}

impl ImageBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the 16-byte volume name field, space-padded on disk.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` exceeds 16 bytes.
    pub fn volume_name(mut self, name: &str) -> Result<Self> {
        let bytes = name.as_bytes();
        if bytes.len() > self.volume_name.len() {
            return Err(Error::Build(format!(
                "volume name exceeds {} bytes: {name:?}",
                self.volume_name.len()
            )));
        }
        self.volume_name[..bytes.len()].copy_from_slice(bytes);
        Ok(self)
    }

    /// Sets the 128-bit volume UUID field (all zero by default).
    pub fn uuid(mut self, uuid: [u8; 16]) -> Self {
        self.uuid = uuid;
        self
    }

    /// Fixes every inode mtime and the superblock build time to `secs`
    /// (nanoseconds zeroed), making the output byte-for-byte reproducible.
    pub fn fixed_time(mut self, secs: u64) -> Self {
        self.fixed_time = Some(secs);
        self
    }

    /// Packs the host directory at `root` into an EROFS image.
    ///
    /// The tree is scanned once to plan metadata and data blocks, then
    /// emitted in a second pass. Regular files are re-read during emission;
    /// if a file's size changed since the scan, the build fails instead of
    /// emitting a torn image.
    ///
    /// # Errors
    ///
    /// Returns an error if `root` is not a directory, if any entry is not a
    /// regular file, directory, or symlink, if a file name exceeds 255
    /// bytes, or if the resulting image exceeds format limits.
    pub fn build_from_dir(&self, root: impl AsRef<Path>) -> Result<Vec<u8>> {
        let root = root.as_ref();
        if !root.is_dir() {
            return Err(Error::Build(format!("{}: not a directory", root.display())));
        }

        let mut tree = self.scan(root, Vec::new())?;

        let mut nid_cursor = FIRST_NID;
        let mut ino_cursor = 1u32;
        assign_nids(&mut tree, &mut nid_cursor, &mut ino_cursor);
        let inode_count = (nid_cursor - FIRST_NID) / (EXTENDED_INODE_SIZE / INODE_SLOT);

        // Inode slots are contiguous from block 0; data blocks start at the
        // first block boundary past the last inode.
        let metadata_end = nid_cursor * INODE_SLOT;
        let mut block_cursor = metadata_end.div_ceil(BLOCK_SIZE as u64);
        let root_raw_nid = tree.nid;
        layout(&mut tree, root_raw_nid, &mut block_cursor)?;

        let total_blocks = block_cursor;
        let image_len = usize::try_from(total_blocks)
            .ok()
            .and_then(|blocks| blocks.checked_mul(BLOCK_SIZE))
            .ok_or_else(|| Error::Build("image exceeds platform limits".to_string()))?;
        let blocks_lo = u32::try_from(total_blocks)
            .map_err(|_| Error::Build("image exceeds 2^32 blocks".to_string()))?;
        let root_nid = u16::try_from(tree.nid)
            .map_err(|_| Error::Build("root nid exceeds 16 bits".to_string()))?;

        let mut image = vec![0u8; image_len];
        self.write_superblock(
            &mut image[SUPERBLOCK_OFFSET..SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE],
            root_nid,
            inode_count,
            blocks_lo,
        );
        emit(&mut image, &tree)?;
        Ok(image)
    }

    fn scan(&self, path: &Path, name: Vec<u8>) -> Result<Node> {
        if name.len() > MAX_NAME_LEN {
            return Err(Error::Build(format!(
                "{}: file name exceeds {MAX_NAME_LEN} bytes",
                path.display()
            )));
        }
        let metadata = fs::symlink_metadata(path)?;
        let (mtime, mtime_nsec) = self.fixed_time.map_or_else(
            || {
                (
                    u64::try_from(metadata.mtime()).unwrap_or(0),
                    u32::try_from(metadata.mtime_nsec()).unwrap_or(0),
                )
            },
            |secs| (secs, 0),
        );
        let mut node = Node {
            name,
            mode: (metadata.mode() & PERMISSION_MASK) as u16,
            uid: metadata.uid(),
            gid: metadata.gid(),
            mtime,
            mtime_nsec,
            nlink: 1,
            nid: 0,
            ino: 0,
            size: 0,
            blkaddr: NULL_BLOCK_ADDR,
            kind: NodeKind::Regular {
                path: path.to_path_buf(),
            },
        };

        let file_type = metadata.file_type();
        if file_type.is_dir() {
            let mut children = Vec::new();
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let child_name = entry.file_name().as_bytes().to_vec();
                children.push(self.scan(&entry.path(), child_name)?);
            }
            children.sort_by(|a, b| a.name.cmp(&b.name));
            node.nlink = 2 + children.iter().filter(|c| c.is_dir()).count() as u32;
            node.mode |= S_IFDIR;
            node.kind = NodeKind::Directory {
                children,
                data: Vec::new(),
            };
        } else if file_type.is_file() {
            node.size = metadata.len();
            node.mode |= S_IFREG;
        } else if file_type.is_symlink() {
            let target = fs::read_link(path)?.as_os_str().as_bytes().to_vec();
            node.size = target.len() as u64;
            node.mode |= S_IFLNK;
            node.kind = NodeKind::Symlink { target };
        } else {
            return Err(Error::Build(format!(
                "{}: unsupported file type (only regular files, directories, and symlinks)",
                path.display()
            )));
        }
        Ok(node)
    }

    fn write_superblock(&self, buf: &mut [u8], root_nid: u16, inos: u64, blocks: u32) {
        debug_assert_eq!(buf.len(), SUPERBLOCK_SIZE);
        let build_time = self.fixed_time.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        });

        let mut put = Cursor::new(buf);
        put.u32(MAGIC_NUMBER);
        put.u32(0); // checksum: EROFS_FEATURE_COMPAT_SB_CHKSUM is not set
        put.u32(0); // feature_compat
        put.u8(BLOCK_BITS);
        put.u8(0); // sb_extslots: 128-byte superblock
        put.u16(root_nid);
        put.u64(inos);
        put.u64(build_time); // epoch
        put.u32(0); // fixed_nsec
        put.u32(blocks);
        put.u32(0); // meta_blkaddr
        put.u32(0); // xattr_blkaddr
        put.bytes(&self.uuid);
        put.bytes(&self.volume_name);
        put.u32(0); // feature_incompat
        put.u16(0); // available_compr_algs
        put.u16(0); // extra_devices
        put.u16(0); // devt_slotoff
        put.u8(0); // dirblkbits: directory block size == block size
        put.u8(0); // xattr_prefix_count
        put.u32(0); // xattr_prefix_start
        put.u64(0); // packed_nid
        put.u8(0); // xattr_filter_reserved
        put.u8(0); // ishare_xattr_prefix_id
        put.u16(0); // reserved
        put.u32(build_time as u32); // build_time
        debug_assert_eq!(put.pos, 112);
        // The remaining bytes (rootnid_8b, reserved2, metabox_nid,
        // reserved3) stay zero: EROFS_FEATURE_INCOMPAT_48BIT and METABOX
        // are not set.
    }
}

struct Node {
    name: Vec<u8>,
    mode: u16,
    uid: u32,
    gid: u32,
    mtime: u64,
    mtime_nsec: u32,
    nlink: u32,
    nid: u64,
    ino: u32,
    size: u64,
    blkaddr: u32,
    kind: NodeKind,
}

enum NodeKind {
    Directory { children: Vec<Node>, data: Vec<u8> },
    Regular { path: PathBuf },
    Symlink { target: Vec<u8> },
}

impl Node {
    fn is_dir(&self) -> bool {
        matches!(self.kind, NodeKind::Directory { .. })
    }

    fn file_type(&self) -> DirentFileType {
        match &self.kind {
            NodeKind::Directory { .. } => DirentFileType::Directory,
            NodeKind::Regular { .. } => DirentFileType::RegularFile,
            NodeKind::Symlink { .. } => DirentFileType::Symlink,
        }
    }
}

const EXTENDED_INODE_SIZE: u64 = 64;

/// Assigns nids and stat inode numbers in pre-order, two 32-byte slots per
/// extended inode.
fn assign_nids(node: &mut Node, nid_cursor: &mut u64, ino_cursor: &mut u32) {
    node.nid = *nid_cursor;
    node.ino = *ino_cursor;
    *nid_cursor += EXTENDED_INODE_SIZE / INODE_SLOT;
    *ino_cursor += 1;
    if let NodeKind::Directory { children, .. } = &mut node.kind {
        for child in children {
            assign_nids(child, nid_cursor, ino_cursor);
        }
    }
}

/// Computes directory payloads and assigns data blocks in pre-order.
fn layout(node: &mut Node, parent_nid: u64, block_cursor: &mut u64) -> Result<()> {
    if let NodeKind::Directory { children, data } = &mut node.kind {
        let mut entries: Vec<DirentPlan> = Vec::with_capacity(children.len() + 2);
        entries.push(DirentPlan {
            nid: node.nid,
            file_type: DirentFileType::Directory,
            name: b".".to_vec(),
        });
        entries.push(DirentPlan {
            nid: parent_nid,
            file_type: DirentFileType::Directory,
            name: b"..".to_vec(),
        });
        entries.extend(children.iter().map(|child| DirentPlan {
            nid: child.nid,
            file_type: child.file_type(),
            name: child.name.clone(),
        }));
        // Canonical order: every entry, dots included, sorted byte-wise so
        // the kernel's per-block binary search stays valid.
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        let (bytes, logical_size) = encode_dirents(&entries);
        node.size = logical_size;
        node.blkaddr = take_blocks(block_cursor, bytes.len() as u64)?;
        *data = bytes;

        for child in children.iter_mut() {
            layout(child, node.nid, block_cursor)?;
        }
        return Ok(());
    }

    if node.size > 0 {
        node.blkaddr = take_blocks(block_cursor, node.size)?;
    }
    Ok(())
}

/// Reserves enough whole blocks to hold `len` payload bytes.
fn take_blocks(block_cursor: &mut u64, len: u64) -> Result<u32> {
    let blkaddr = u32::try_from(*block_cursor)
        .map_err(|_| Error::Build("image exceeds 2^32 blocks".to_string()))?;
    *block_cursor += len.div_ceil(BLOCK_SIZE as u64);
    Ok(blkaddr)
}

struct DirentPlan {
    nid: u64,
    file_type: DirentFileType,
    name: Vec<u8>,
}

/// Packs sorted dirents into blocks: entries that no longer fit move to the
/// next block. Returns the zero-padded block bytes and the logical directory
/// size (full blocks plus the used bytes of the final block).
fn encode_dirents(entries: &[DirentPlan]) -> (Vec<u8>, u64) {
    debug_assert!(!entries.is_empty());
    let mut data = Vec::new();
    let mut logical_size = 0u64;
    let mut block_start = 0usize;
    let mut used = 0usize;

    for (index, entry) in entries.iter().enumerate() {
        let needed = DIRENT_SIZE + entry.name.len();
        if used + needed > BLOCK_SIZE {
            write_dir_block(&mut data, &entries[block_start..index]);
            logical_size += BLOCK_SIZE as u64;
            block_start = index;
            used = 0;
        }
        used += needed;
    }
    write_dir_block(&mut data, &entries[block_start..]);
    logical_size += used as u64;
    (data, logical_size)
}
/// Appends one full dirent block to `data`: the dirent array first, names
/// directly behind it, and zero padding up to the block size.
fn write_dir_block(data: &mut Vec<u8>, entries: &[DirentPlan]) {
    let block_base = data.len();
    let header = entries.len() * DIRENT_SIZE;
    data.resize(block_base + BLOCK_SIZE, 0);

    let mut name_offset = header;
    for (slot, entry) in entries.iter().enumerate() {
        let dirent_offset = block_base + slot * DIRENT_SIZE;
        data[dirent_offset..dirent_offset + 8].copy_from_slice(&entry.nid.to_le_bytes());
        data[dirent_offset + 8..dirent_offset + 10]
            .copy_from_slice(&(name_offset as u16).to_le_bytes());
        data[dirent_offset + 10] = entry.file_type as u8;
        let name_start = block_base + name_offset;
        data[name_start..name_start + entry.name.len()].copy_from_slice(&entry.name);
        name_offset += entry.name.len();
    }
}

/// Writes the inode and payload of `node` and its descendants into `image`.
fn emit(image: &mut [u8], node: &Node) -> Result<()> {
    write_inode(image, node);

    match &node.kind {
        NodeKind::Directory { children, data } => {
            let start = node.blkaddr as usize * BLOCK_SIZE;
            image[start..start + data.len()].copy_from_slice(data);
            for child in children {
                emit(image, child)?;
            }
        }
        NodeKind::Regular { path } => {
            if node.size > 0 {
                let bytes = fs::read(path)?;
                if bytes.len() as u64 != node.size {
                    return Err(Error::Build(format!(
                        "{}: file changed while building the image",
                        path.display()
                    )));
                }
                let start = node.blkaddr as usize * BLOCK_SIZE;
                image[start..start + bytes.len()].copy_from_slice(&bytes);
            }
        }
        NodeKind::Symlink { target } => {
            if !target.is_empty() {
                let start = node.blkaddr as usize * BLOCK_SIZE;
                image[start..start + target.len()].copy_from_slice(target);
            }
        }
    }
    Ok(())
}

/// Writes one 64-byte extended inode at `nid * 32`.
fn write_inode(image: &mut [u8], node: &Node) {
    let offset = node.nid as usize * INODE_SLOT as usize;
    let mut put = Cursor::new(&mut image[offset..offset + EXTENDED_INODE_SIZE as usize]);
    put.u16(FORMAT_EXTENDED_FLAT_PLAIN);
    put.u16(0); // i_xattr_icount
    put.u16(node.mode);
    put.u16(0); // i_nb: startblk_hi, unused below 2^32 blocks
    put.u64(node.size);
    put.u32(node.blkaddr);
    put.u32(node.ino);
    put.u32(node.uid);
    put.u32(node.gid);
    put.u64(node.mtime);
    put.u32(node.mtime_nsec);
    put.u32(node.nlink);
    debug_assert_eq!(put.pos, 48);
    // i_reserved2 stays zero.
}

/// Little-endian field writer over a byte buffer.
struct Cursor<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn u8(&mut self, value: u8) {
        self.buf[self.pos] = value;
        self.pos += 1;
    }

    fn u16(&mut self, value: u16) {
        self.bytes(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_le_bytes());
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(nid: u64, name: &str) -> DirentPlan {
        DirentPlan {
            nid,
            file_type: DirentFileType::RegularFile,
            name: name.as_bytes().to_vec(),
        }
    }

    /// Decodes the dirent array of the block at `base` in `data`.
    fn decode_block(data: &[u8], base: usize, used: usize) -> Vec<(u64, u8, Vec<u8>)> {
        let block = &data[base..base + used];
        let count = u16::from_le_bytes([block[8], block[9]]) as usize / DIRENT_SIZE;
        (0..count)
            .map(|i| {
                let d = &block[i * DIRENT_SIZE..(i + 1) * DIRENT_SIZE];
                let nid = u64::from_le_bytes(d[..8].try_into().unwrap());
                let name_off = u16::from_le_bytes(d[8..10].try_into().unwrap()) as usize;
                let name_end = if i + 1 < count {
                    u16::from_le_bytes([
                        block[(i + 1) * DIRENT_SIZE + 8],
                        block[(i + 1) * DIRENT_SIZE + 9],
                    ]) as usize
                } else {
                    // Trim zero padding behind the last name.
                    block[name_off..]
                        .iter()
                        .position(|&b| b == 0)
                        .map_or(block.len(), |pos| name_off + pos)
                };
                (nid, d[10], block[name_off..name_end].to_vec())
            })
            .collect()
    }

    #[test]
    fn encode_dirents_packs_names_behind_header() {
        let entries = [plan(36, "."), plan(34, ".."), plan(38, "hello")];
        let (data, size) = encode_dirents(&entries);
        assert_eq!(data.len(), BLOCK_SIZE);
        assert_eq!(size, (3 * DIRENT_SIZE + 1 + 2 + 5) as u64);
        let decoded = decode_block(&data, 0, size as usize);
        assert_eq!(
            decoded,
            vec![
                (36, DirentFileType::RegularFile as u8, b".".to_vec()),
                (34, DirentFileType::RegularFile as u8, b"..".to_vec()),
                (38, DirentFileType::RegularFile as u8, b"hello".to_vec()),
            ]
        );
    }

    #[test]
    fn encode_dirents_spills_to_next_block() {
        // Each entry costs 12 + 14 = 26 bytes; 157 fill a block (4082
        // bytes), the 158th would exceed 4096, so 43 spill over.
        let entries: Vec<_> = (0..200)
            .map(|i| plan(36 + i * 2, &format!("entry-{i:08}")))
            .collect();
        let (data, size) = encode_dirents(&entries);
        assert_eq!(data.len(), 2 * BLOCK_SIZE);
        let first_count = u16::from_le_bytes([data[8], data[9]]) as usize / DIRENT_SIZE;
        assert_eq!(first_count, 157);
        assert_eq!(size, BLOCK_SIZE as u64 + (43 * (DIRENT_SIZE + 14)) as u64);
        let decoded = decode_block(&data, BLOCK_SIZE, (size as usize) - BLOCK_SIZE);
        assert_eq!(decoded.len(), 43);
        assert_eq!(decoded[0].2, b"entry-00000157");
    }

    #[test]
    fn encode_dirents_exact_block_boundary_starts_fresh_block() {
        // Fill one block exactly: 162 entries with 13-byte names cost
        // 162 * 25 = 4050 bytes; one 34-byte name adds 46 -> exactly 4096.
        let mut entries: Vec<_> = (0..162)
            .map(|i| plan(36 + i * 2, &format!("entry-{i:07}")))
            .collect();
        entries.push(plan(999, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")); // 34 bytes: 12+34=46
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let used: usize = entries.iter().map(|e| DIRENT_SIZE + e.name.len()).sum();
        assert_eq!(used, BLOCK_SIZE);
        entries.push(plan(1001, "overflow"));
        let (data, size) = encode_dirents(&entries);
        assert_eq!(data.len(), 2 * BLOCK_SIZE);
        assert_eq!(size, BLOCK_SIZE as u64 + (DIRENT_SIZE + 8) as u64);
        let decoded = decode_block(&data, BLOCK_SIZE, DIRENT_SIZE + 8);
        assert_eq!(decoded, vec![(1001, 1, b"overflow".to_vec())]);
    }
}
