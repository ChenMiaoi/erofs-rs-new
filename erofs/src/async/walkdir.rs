use std::collections::HashSet;
use std::vec::Vec;

use super::EroFS;
use super::dirent::ReadDir;
use crate::backend::AsyncImage;
use crate::dirent::DirEntry;
use crate::{Error, Result, types::Inode};
use typed_path::UnixPath;

/// Hard cap on recursion depth when no explicit limit is set.
const DEFAULT_MAX_DEPTH: usize = 256;

/// An async iterator for recursively walking a directory tree.
///
/// The iterator is fused: once an error is yielded, iteration ends and
/// subsequent calls to `next_entry()` return `None`.
pub struct WalkDir<'a, I: AsyncImage> {
    erofs: &'a EroFS<I>,
    dir_stack: Vec<(usize, u64, ReadDir<'a, I>)>,
    ancestor_nids: HashSet<u64>,
    max_depth: usize,
    poisoned: bool,
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

impl<'a, I: AsyncImage> WalkDir<'a, I> {
    pub(crate) async fn new(erofs: &'a EroFS<I>, root: impl AsRef<UnixPath>) -> Result<Self> {
        let root_nid;
        let read_dir = {
            let inode = erofs
                .get_path_inode(root.as_ref())
                .await?
                .ok_or_else(|| Error::PathNotFound(root.as_ref().to_string_lossy().into_owned()))?;

            if !inode.file_type().is_dir() {
                return Err(Error::NotADirectory(
                    root.as_ref().to_string_lossy().into_owned(),
                ));
            }

            root_nid = inode.id();
            ReadDir::new(erofs, inode, root).await?
        };
        Ok(WalkDir {
            erofs,
            dir_stack: vec![(1, root_nid, read_dir)],
            ancestor_nids: HashSet::from([root_nid]),
            max_depth: 0,
            poisoned: false,
        })
    }

    /// Sets the maximum depth to descend into subdirectories.
    ///
    /// A depth of 1 means only immediate children are returned (like `read_dir`).
    /// An explicit depth of `n > 0` means exactly `n` levels.
    /// A depth of 0 (the default) means recursion is bounded by a hard cap of
    /// 256 levels, guarding against maliciously deep directory trees.
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    async fn get_walk_dir_entry(
        &mut self,
        dir_entry: DirEntry,
        depth: usize,
    ) -> Result<WalkDirEntry> {
        let inode = self.erofs.get_inode(dir_entry.nid()).await?;

        let max_depth = if self.max_depth == 0 {
            DEFAULT_MAX_DEPTH
        } else {
            self.max_depth
        };
        if dir_entry.file_type().is_dir() {
            if depth >= max_depth {
                return Err(Error::CorruptedData(
                    "directory traversal depth limit".into(),
                ));
            }
            if self.ancestor_nids.contains(&inode.id()) {
                return Err(Error::CorruptedData("directory traversal cycle".into()));
            }
            let child_dir = ReadDir::new(self.erofs, inode, dir_entry.path()).await?;
            self.dir_stack.push((depth + 1, inode.id(), child_dir));
            self.ancestor_nids.insert(inode.id());
        }

        Ok(WalkDirEntry {
            depth,
            dir_entry,
            inode,
        })
    }

    pub async fn next_entry(&mut self) -> Option<Result<WalkDirEntry>> {
        if self.poisoned {
            return None;
        }
        loop {
            let (depth, next_item) = {
                let (depth, _, dir) = self.dir_stack.last_mut()?;
                let next = dir.next_entry().await;
                (*depth, next)
            };

            match next_item {
                Ok(Some(entry)) => {
                    let result = self.get_walk_dir_entry(entry, depth).await;
                    if result.is_err() {
                        self.poisoned = true;
                    }
                    return Some(result);
                }
                Ok(None) => {
                    if let Some((_, nid, _)) = self.dir_stack.pop() {
                        self.ancestor_nids.remove(&nid);
                    }
                }
                Err(e) => {
                    self.poisoned = true;
                    return Some(Err(e));
                }
            }
        }
    }
}
