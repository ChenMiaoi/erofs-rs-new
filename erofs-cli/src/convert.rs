use std::{fs::File, io::Read, os::unix::fs::PermissionsExt, time::UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::Args;
use erofs_rs::{EroFS, backend::MmapImage};
use tar::Header;
use typed_path::{UnixComponent, UnixPath};
const MAX_SYMLINK_TARGET_BYTES: usize = 4096;

#[derive(Args, Debug)]
pub struct ConvertArgs {
    path: String,
    #[clap(short, long, default_value = "/")]
    root: String,
    #[clap(short, long)]
    output: String,
    #[clap(short, long)]
    format: Option<String>,
}

/// Returns true if `path` is a non-empty relative path that cannot escape the
/// archive root (no root or parent-directory components). Defense in depth
/// against crafted images with `..` dirent names.
fn is_safe_relative_path(path: &UnixPath) -> bool {
    !path.as_bytes().is_empty()
        && path
            .components()
            .all(|c| matches!(c, UnixComponent::Normal(_) | UnixComponent::CurDir))
}

pub fn convert(args: ConvertArgs) -> Result<()> {
    // SAFETY: the image file is opened read-only and not modified while mapped
    let image = unsafe { MmapImage::new_from_path(args.path)? };
    let fs = EroFS::new(image)?;

    let out_file = File::create(args.output)?;
    let mut tar = tar::Builder::new(out_file);

    for entry in fs.walk_dir(args.root)? {
        let entry = entry.context("read entry failed")?;

        let path = entry.dir_entry.path();
        let relative = path.strip_prefix("/")?;
        if !is_safe_relative_path(relative) {
            eprintln!(
                "warning: skipping unsafe path: {}",
                relative.to_string_lossy()
            );
            continue;
        }

        let mut header = Header::new_gnu();
        header.set_path(relative.to_string_lossy().into_owned())?;
        header.set_mode(entry.inode.permissions().mode());
        if let Some(time) = entry.inode.modified() {
            header.set_mtime(time.duration_since(UNIX_EPOCH)?.as_secs());
        }

        let file_type = entry.dir_entry.file_type();
        if file_type.is_dir() {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_cksum();
            tar.append(&header, std::io::empty())?;
        } else if file_type.is_symlink() {
            let mut target = Vec::with_capacity(MAX_SYMLINK_TARGET_BYTES);
            let mut target_reader = fs
                .open_inode_data(entry.inode)?
                .take((MAX_SYMLINK_TARGET_BYTES + 1) as u64);
            target_reader.read_to_end(&mut target)?;
            if target.len() > MAX_SYMLINK_TARGET_BYTES {
                bail!("symlink target exceeds {} bytes", MAX_SYMLINK_TARGET_BYTES);
            }
            let target_name = String::from_utf8_lossy(&target).into_owned();
            if !is_safe_relative_path(UnixPath::new(&target_name)) {
                bail!("unsafe symlink target");
            }
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_link_name(target_name)?;
            header.set_size(0);
            header.set_cksum();
            tar.append(&header, std::io::empty())?;
        } else if file_type.is_file() {
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(entry.inode.data_size() as u64);
            header.set_cksum();

            tar.append(&header, fs.open_inode_file(entry.inode)?)?;
        } else {
            eprintln!(
                "warning: skipping unsupported file type {:?}: {}",
                file_type,
                relative.to_string_lossy()
            );
        }
    }

    tar.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_safe_relative_path;
    use typed_path::UnixPath;

    #[test]
    fn safe_relative_path_accepts_normal_paths() {
        assert!(is_safe_relative_path(UnixPath::new("a/b/c")));
        assert!(is_safe_relative_path(UnixPath::new("./a")));
        assert!(is_safe_relative_path(UnixPath::new("..data/file")));
    }

    #[test]
    fn safe_relative_path_rejects_traversal_and_empty() {
        assert!(!is_safe_relative_path(UnixPath::new("../etc/passwd")));
        assert!(!is_safe_relative_path(UnixPath::new("a/../../b")));
        assert!(!is_safe_relative_path(UnixPath::new("/abs/path")));
        assert!(!is_safe_relative_path(UnixPath::new("")));
    }
}
