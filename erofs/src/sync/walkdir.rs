use std::vec::Vec;

use super::EroFS;
use super::dirent::ReadDir;
use crate::backend::Image;
use crate::dirent::DirEntry;
use crate::{Error, Result, types::Inode};
use typed_path::UnixPath;

/// An iterator for recursively walking a directory tree.
///
/// Created by [`EroFS::walk_dir`] or [`EroFS::read_dir`].
#[derive(Debug)]
pub struct WalkDir<'a, I: Image> {
    erofs: &'a EroFS<I>,
    dir_stack: Vec<(usize, ReadDir<'a, I>)>,
    ancestor_nids: Vec<u64>,
    max_depth: usize,
}

/// A single entry returned by [`WalkDir`].
pub struct WalkDirEntry {
    /// The depth of this entry relative to the starting directory (1-indexed).
    pub depth: usize,
    /// The directory entry containing file name and type.
    pub dir_entry: DirEntry,
    /// The inode containing file metadata.
    pub inode: Inode,
}

impl<'a, I: Image> WalkDir<'a, I> {
    pub(crate) fn new<P: AsRef<UnixPath>>(erofs: &'a EroFS<I>, root: P) -> Result<Self> {
        let root_nid;
        let read_dir = {
            let inode = erofs
                .get_path_inode(&root)?
                .ok_or_else(|| Error::PathNotFound(root.as_ref().to_string_lossy().into_owned()))?;

            if !inode.file_type().is_dir() {
                return Err(Error::NotADirectory(
                    root.as_ref().to_string_lossy().into_owned(),
                ));
            }

            root_nid = inode.id();
            ReadDir::new(erofs, inode, root)?
        };
        Ok(WalkDir {
            erofs,
            dir_stack: vec![(1, read_dir)],
            ancestor_nids: vec![root_nid],
            max_depth: 0,
        })
    }

    /// Sets the maximum depth to descend into subdirectories.
    ///
    /// A depth of 1 means only immediate children are returned (like `read_dir`).
    /// A depth of 0 (the default) means unlimited depth.
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    fn get_walk_dir_entry(&mut self, dir_entry: DirEntry, depth: usize) -> Result<WalkDirEntry> {
        let inode = self.erofs.get_inode(dir_entry.nid())?;

        if (depth < self.max_depth || self.max_depth == 0) && dir_entry.file_type().is_dir() {
            if contains_nid(&self.ancestor_nids, inode.id()) {
                return Err(Error::CorruptedData("directory traversal cycle".into()));
            }
            let child_dir = ReadDir::new(self.erofs, inode, dir_entry.path())?;
            self.dir_stack.push((depth + 1, child_dir));
            self.ancestor_nids.push(inode.id());
        }

        Ok(WalkDirEntry {
            depth,
            dir_entry,
            inode,
        })
    }

    fn next_entry(&mut self) -> Option<Result<WalkDirEntry>> {
        loop {
            let (depth, next_item) = {
                let (depth, dir) = self.dir_stack.last_mut()?;
                (*depth, dir.next())
            };

            match next_item {
                Some(Ok(entry)) => return Some(self.get_walk_dir_entry(entry, depth)),
                Some(Err(e)) => return Some(Err(e)),
                None => {
                    self.dir_stack.pop();
                    self.ancestor_nids.pop();
                }
            }
        }
    }
}

fn contains_nid(nids: &[u64], nid: u64) -> bool {
    nids.contains(&nid)
}

impl<'a, I: Image> Iterator for WalkDir<'a, I> {
    type Item = Result<WalkDirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_entry()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EroFS, backend::SliceImage, types::MAGIC_NUMBER};

    #[test]
    fn rejects_directory_ancestor_cycle() {
        const BLOCK_SIZE: usize = 4096;
        const SUPERBLOCK_OFFSET: usize = 1024;
        let mut image = vec![0; 3 * BLOCK_SIZE];
        image[SUPERBLOCK_OFFSET..SUPERBLOCK_OFFSET + 4]
            .copy_from_slice(&MAGIC_NUMBER.to_le_bytes());
        image[SUPERBLOCK_OFFSET + 12] = 12;
        image[SUPERBLOCK_OFFSET + 40..SUPERBLOCK_OFFSET + 44].copy_from_slice(&1_u32.to_le_bytes());
        image[BLOCK_SIZE + 4..BLOCK_SIZE + 6].copy_from_slice(&0o040755_u16.to_le_bytes());
        image[BLOCK_SIZE + 8..BLOCK_SIZE + 12].copy_from_slice(&16_u32.to_le_bytes());
        image[BLOCK_SIZE + 16..BLOCK_SIZE + 20].copy_from_slice(&2_u32.to_le_bytes());
        image[2 * BLOCK_SIZE + 8..2 * BLOCK_SIZE + 10].copy_from_slice(&12_u16.to_le_bytes());
        image[2 * BLOCK_SIZE + 10] = 2;
        image[2 * BLOCK_SIZE + 12..2 * BLOCK_SIZE + 16].copy_from_slice(b"loop");

        let fs = EroFS::new(SliceImage::new(&image)).unwrap();
        let mut walker = fs.walk_dir("/").unwrap();
        assert!(
            matches!(walker.next(), Some(Err(Error::CorruptedData(message))) if message == "directory traversal cycle")
        );
    }

    #[test]
    fn detects_directory_ancestor_cycle() {
        assert!(contains_nid(&[1, 2, 3], 1));
        assert!(contains_nid(&[1, 2, 3], 3));
        assert!(!contains_nid(&[1, 2, 3], 4));
    }
}
