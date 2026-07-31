use core::{cmp, hint};
use std::string::{String, ToString};

use binrw::{BinRead, io::Cursor};
use typed_path::UnixPathBuf;

use crate::{
    Error, Result,
    types::{Dirent, DirentFileType},
};

pub fn find_nodeid_by_name(name: &[u8], data: &[u8]) -> Result<Option<u64>> {
    let dirent = read_nth_dirent(data, 0)?;
    let n = dirent.name_off as usize / Dirent::size();
    if n <= 2 {
        // Only "." and ".."
        return Ok(None);
    }

    let offset = 2;
    let mut size = n - offset;
    let mut base = 0usize;
    while size > 1 {
        let half = size / 2;
        let mid = base + half;

        let cmp = {
            let (_, entry_name) = read_nth_id_name(data, mid + offset, n)?;
            entry_name.cmp(name)
        };
        base = hint::select_unpredictable(cmp == cmp::Ordering::Greater, base, mid);

        size -= half;
    }

    let (inner_nid, cmp) = {
        let (nid, entry_name) = read_nth_id_name(data, base + offset, n)?;
        let cmp = entry_name.cmp(name);
        (nid, cmp)
    };
    if cmp != cmp::Ordering::Equal {
        return Ok(None);
    }

    Ok(Some(inner_nid))
}

fn read_nth_id_name(data: &[u8], n: usize, max: usize) -> Result<(u64, &[u8])> {
    let dirent = read_nth_dirent(data, n)?;
    let name_start = dirent.name_off as usize;
    let name_end = if n < max - 1 {
        let dirent = read_nth_dirent(data, n + 1)?;
        dirent.name_off as usize
    } else {
        data.len()
    };

    if name_end < name_start || name_end > data.len() {
        return Err(Error::CorruptedData(
            "invalid directory entry name offset".to_string(),
        ));
    }
    let name = &data[name_start..name_end];
    // Trim trailing null bytes
    let name = name
        .iter()
        .position(|&b| b == 0)
        .map_or(name, |i| &name[..i]);
    if name.contains(&b'/') {
        return Err(Error::CorruptedData(
            "directory entry name contains '/'".to_string(),
        ));
    }

    Ok((dirent.nid, name))
}

pub fn read_nth_dirent(data: &[u8], n: usize) -> Result<Dirent> {
    let start = n * Dirent::size();
    let slice = data
        .get(start..)
        .ok_or_else(|| Error::OutOfBounds("failed to get inode data".to_string()))?;
    let dirent = Dirent::read(&mut Cursor::new(slice))?;
    Ok(dirent)
}

#[derive(Debug)]
pub struct DirentBlock<D: AsRef<[u8]>> {
    data: D,
    root: UnixPathBuf,
    dirent: Dirent,
    i: usize,
    n: usize,
    poisoned: bool,
}

impl<D: AsRef<[u8]>> DirentBlock<D> {
    pub(crate) fn new(root: UnixPathBuf, data: D) -> Result<Self> {
        let dirent = read_nth_dirent(data.as_ref(), 0)?;
        let n = dirent.name_off as usize / Dirent::size();
        Ok(Self {
            root,
            data,
            dirent,
            i: 0,
            n,
            poisoned: false,
        })
    }

    pub(crate) fn block_size(&self) -> usize {
        self.data.as_ref().len()
    }

    pub(crate) fn next_entry(&mut self) -> Result<Option<DirEntry>> {
        if self.poisoned {
            return Ok(None);
        }
        match self.try_next_entry() {
            Ok(entry) => Ok(entry),
            Err(e) => {
                // Fused: once an error occurs, iteration ends.
                self.poisoned = true;
                Err(e)
            }
        }
    }

    fn try_next_entry(&mut self) -> Result<Option<DirEntry>> {
        let data = self.data.as_ref();
        while self.i < self.n {
            let dirent = self.dirent;
            let name_start = dirent.name_off as usize;
            // Validate the next dirent and the name range using locals first;
            // state is committed only after every fallible check has passed.
            let (next_dirent, name_end) = if self.i < self.n - 1 {
                let next_dirent = read_nth_dirent(data, self.i + 1)?;
                (Some(next_dirent), next_dirent.name_off as usize)
            } else {
                (None, data.len())
            };

            if name_end < name_start || name_end > data.len() {
                return Err(Error::CorruptedData(
                    "invalid directory entry name offset".to_string(),
                ));
            }

            let name: String = String::from_utf8_lossy(&data[name_start..name_end])
                .trim_end_matches('\0')
                .into();
            if name.contains('/') {
                return Err(Error::CorruptedData(
                    "directory entry name contains '/'".to_string(),
                ));
            }
            let file_type = DirentFileType::try_from(dirent.file_type)?;

            // All fallible checks passed; commit state.
            if let Some(next_dirent) = next_dirent {
                self.dirent = next_dirent;
            }
            self.i += 1;

            if name.as_str() == "." || name.as_str() == ".." {
                continue;
            }

            let entry = DirEntry {
                dir: self.root.clone(),
                nid: dirent.nid,
                file_type,
                file_name: name,
            };
            return Ok(Some(entry));
        }
        Ok(None)
    }
}

impl<D: AsRef<[u8]>> Iterator for DirentBlock<D> {
    type Item = Result<DirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i >= self.n {
            None
        } else {
            self.next_entry().transpose()
        }
    }
}

/// A directory entry within an EROFS filesystem.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub(crate) dir: UnixPathBuf,
    pub(crate) nid: u64,
    pub(crate) file_type: DirentFileType,
    pub(crate) file_name: String,
}

impl DirEntry {
    /// Returns the file type of this entry.
    pub fn file_type(&self) -> DirentFileType {
        self.file_type
    }

    /// Returns the file name of this entry.
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Returns the full path of this entry.
    pub fn path(&self) -> UnixPathBuf {
        self.dir.join(&self.file_name)
    }

    /// Returns the node ID (inode number) of this entry.
    pub fn nid(&self) -> u64 {
        self.nid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use typed_path::UnixPath;

    fn dirent_bytes(nid: u64, name_off: u16, file_type: u8) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        bytes[..8].copy_from_slice(&nid.to_le_bytes());
        bytes[8..10].copy_from_slice(&name_off.to_le_bytes());
        bytes[10] = file_type;
        bytes
    }

    /// Builds a directory block with `entries` of (nid, file_type, name).
    fn dir_block(entries: &[(u64, u8, &str)]) -> Vec<u8> {
        let mut data = Vec::new();
        let mut name_off = (entries.len() * Dirent::size()) as u16;
        for (nid, file_type, name) in entries {
            data.extend_from_slice(&dirent_bytes(*nid, name_off, *file_type));
            name_off += name.len() as u16;
        }
        for (_, _, name) in entries {
            data.extend_from_slice(name.as_bytes());
        }
        data
    }

    #[test]
    fn next_entry_preserves_state_and_is_fused_on_error() {
        let mut data = dir_block(&[(1, 2, "."), (2, 2, ".."), (3, 1, "ok")]);
        // Corrupt the last dirent's name offset to point past the block.
        let last = 2 * Dirent::size();
        data[last + 8..last + 10].copy_from_slice(&u16::MAX.to_le_bytes());
        let valid_name_off =
            u16::from_le_bytes([data[Dirent::size() + 8], data[Dirent::size() + 9]]);

        let mut block = DirentBlock::new(UnixPath::new("/").to_path_buf(), data).unwrap();
        assert!(matches!(
            block.next(),
            Some(Err(Error::CorruptedData(message))) if message == "invalid directory entry name offset"
        ));
        // The failing dirent was not committed: index and cached dirent are
        // untouched, so iteration cannot skip or repeat entries.
        assert_eq!(block.i, 1);
        let cached_name_off = { block.dirent }.name_off;
        assert_eq!(cached_name_off, valid_name_off);
        // Fused: subsequent calls end iteration instead of repeating the error.
        assert!(block.next().is_none());
        assert!(block.next().is_none());
    }

    #[test]
    fn next_entry_rejects_name_containing_slash() {
        let data = dir_block(&[(1, 2, "."), (2, 2, ".."), (3, 1, "a/b")]);
        let mut block = DirentBlock::new(UnixPath::new("/").to_path_buf(), data).unwrap();
        assert!(matches!(
            block.next(),
            Some(Err(Error::CorruptedData(message))) if message == "directory entry name contains '/'"
        ));
        assert!(block.next().is_none());
    }

    #[test]
    fn find_nodeid_by_name_rejects_name_containing_slash() {
        let data = dir_block(&[(1, 2, "."), (2, 2, ".."), (3, 1, "a/b")]);
        assert!(matches!(
            find_nodeid_by_name(b"a/b", &data),
            Err(Error::CorruptedData(message)) if message == "directory entry name contains '/'"
        ));
    }
}
