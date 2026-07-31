use std::{
    cmp, format,
    io::{Read, Result},
};

use bytes::Bytes;

use super::EroFS;
use crate::backend::Image;
use crate::types::Inode;

/// A handle to a file within an EROFS filesystem.
///
/// `File` implements [`std::io::Read`], allowing you to read the file's contents
/// using standard I/O methods like `read`, `read_to_end`, or `read_to_string`.
///
/// # Example
///
/// ```no_run
/// use std::io::Read;
/// use erofs_rs::EroFS;
/// use erofs_rs::backend::MmapImage;
///
/// // SAFETY: image file is not modified while mapped
/// let image = unsafe { MmapImage::new_from_path("image.erofs") }.unwrap();
/// let fs = EroFS::new(image).unwrap();
///
/// let mut file = fs.open("/etc/passwd").unwrap();
/// let mut content = Vec::new();
/// file.read_to_end(&mut content).unwrap();
/// ```
#[derive(Debug)]
pub struct File<'a, I: Image> {
    inode: Inode,
    erofs: &'a EroFS<I>,
    offset: usize,
    buf: Option<Bytes>,
}

impl<'a, I: Image> File<'a, I> {
    pub(crate) fn new(inode: Inode, erofs: &'a EroFS<I>) -> Self {
        Self {
            inode,
            erofs,
            offset: 0,
            buf: None,
        }
    }

    /// Returns the size of the file in bytes.
    pub fn size(&self) -> usize {
        self.inode.data_size()
    }
}

impl<'a, I: Image> Read for File<'a, I> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let data_size = self
            .inode
            .data_size_checked()
            .map_err(|e| std::io::Error::other(format!("invalid file size: {e}")))?;
        if self.offset >= data_size {
            return Ok(0);
        }

        if let Some(ref data) = self.buf {
            let offset = self.offset % self.erofs.block_size();
            let data_remaining = data.len().saturating_sub(offset);
            let n = cmp::min(buf.len(), data_remaining);
            buf[..n].copy_from_slice(&data[offset..offset + n]);
            self.offset += n;
            if n == data_remaining {
                self.buf = None;
            }
            return Ok(n);
        }

        let block_size = self.erofs.block_size();
        let cur_offset = self.offset;
        let block = self.erofs.get_inode_block(&self.inode, cur_offset);

        let block = block.map_err(|e| std::io::Error::other(format!("read block failed: {e}")))?;

        let offset = cur_offset % block_size;
        let n = cmp::min(buf.len(), block.len().saturating_sub(offset));
        buf[..n].copy_from_slice(&block[offset..offset + n]);
        self.offset += n;
        if n < block.len() - offset {
            self.buf = Some(Bytes::copy_from_slice(block));
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use crate::backend::SliceImage;
    use crate::types::{MAGIC_NUMBER, SUPER_BLOCK_OFFSET};

    use super::super::EroFS;

    #[test]
    fn empty_buffer_does_not_advance_the_file() {
        let mut image = [0; 3 * 4096];
        image[SUPER_BLOCK_OFFSET..SUPER_BLOCK_OFFSET + 4]
            .copy_from_slice(&MAGIC_NUMBER.to_le_bytes());
        image[SUPER_BLOCK_OFFSET + 12] = 12;
        image[SUPER_BLOCK_OFFSET + 40..SUPER_BLOCK_OFFSET + 44]
            .copy_from_slice(&1_u32.to_le_bytes());
        image[4096 + 4..4096 + 6].copy_from_slice(&0o100644_u16.to_le_bytes());
        image[4096 + 8..4096 + 12].copy_from_slice(&1_u32.to_le_bytes());
        image[4096 + 16..4096 + 20].copy_from_slice(&2_u32.to_le_bytes());
        image[8192] = b'x';
        let fs = EroFS::new(SliceImage::new(&image)).unwrap();
        let inode = fs.get_inode(0).unwrap();
        let mut file = fs.open_inode_file(inode).unwrap();

        assert_eq!(file.read(&mut []).unwrap(), 0);
        let mut bytes = [0; 1];
        assert_eq!(file.read(&mut bytes).unwrap(), 1);
        assert_eq!(bytes, [b'x']);
    }
}
