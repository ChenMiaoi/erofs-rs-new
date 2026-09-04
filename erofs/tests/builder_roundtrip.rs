//! Round-trip tests: build an image from a host directory tree and read it
//! back through the crate's own reader.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use erofs_rs::EroFS;
use erofs_rs::backend::SliceImage;
use erofs_rs::builder::ImageBuilder;

const FIXED_TIME: u64 = 1_700_000_000;

static TEMP_COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "erofs-builder-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Creates the shared fixture tree under `root`.
fn create_fixture(root: &Path) {
    fs::write(root.join("empty"), b"").unwrap();
    fs::write(root.join("hello.txt"), b"hello erofs\n").unwrap();
    let big: Vec<u8> = (0..10_000u32).flat_map(|i| i.to_le_bytes()).collect();
    fs::write(root.join("big.bin"), &big).unwrap();
    fs::write(root.join("exact.bin"), vec![0xabu8; 4096]).unwrap();
    // Sorts before ".": exercises dirent ordering where dots are not first.
    fs::write(root.join("!leading"), b"bang\n").unwrap();
    fs::write(root.join("héllo.txt"), b"unicode\n").unwrap();

    fs::create_dir(root.join("sub")).unwrap();
    fs::write(root.join("sub").join("a.txt"), b"a\n").unwrap();
    fs::create_dir(root.join("sub").join("deep")).unwrap();
    fs::write(root.join("sub").join("deep").join("b.txt"), b"b\n").unwrap();

    // Enough entries to span multiple dirent blocks.
    let many = root.join("many");
    fs::create_dir(&many).unwrap();
    for i in 0..200 {
        fs::write(many.join(format!("file-{i:04}")), format!("content-{i}\n")).unwrap();
    }

    symlink("hello.txt", root.join("link.txt")).unwrap();
    symlink("sub", root.join("dirlink")).unwrap();
}

fn build_fixture_image(root: &Path) -> Vec<u8> {
    ImageBuilder::new()
        .volume_name("test")
        .unwrap()
        .fixed_time(FIXED_TIME)
        .build_from_dir(root)
        .unwrap()
}

fn collect_tree(root: &Path) -> BTreeMap<String, (u8, Vec<u8>)> {
    let mut expected = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            let md = fs::symlink_metadata(&path).unwrap();
            if md.file_type().is_dir() {
                expected.insert(rel, (2, Vec::new()));
                stack.push(path);
            } else if md.file_type().is_symlink() {
                let target = fs::read_link(&path).unwrap().into_os_string().into_vec();
                expected.insert(rel, (7, target));
            } else {
                expected.insert(rel, (1, fs::read(&path).unwrap()));
            }
        }
    }
    expected
}

#[test]
fn roundtrip_fixture_tree_matches_host() {
    let temp = TempDir::new();
    create_fixture(&temp.0);
    let expected = collect_tree(&temp.0);

    let image = build_fixture_image(&temp.0);
    let fsys = EroFS::new(SliceImage::new(&image)).unwrap();

    let sb = fsys.super_block();
    assert_eq!(sb.blk_size_bits, 12);
    assert_eq!(&sb.volume_name[..4], b"test");

    let mut actual = BTreeMap::new();
    for entry in fsys.walk_dir("/").unwrap() {
        let entry = entry.unwrap();
        let path = entry.dir_entry.path().to_string_lossy().into_owned();
        let rel = path.trim_start_matches('/').to_string();
        let ftype = entry.dir_entry.file_type();
        if ftype.is_dir() {
            actual.insert(rel, (2u8, Vec::new()));
        } else if ftype.is_symlink() {
            let inode = fsys.get_inode(entry.dir_entry.nid()).unwrap();
            let mut target = Vec::new();
            fsys.open_inode_data(inode)
                .unwrap()
                .read_to_end(&mut target)
                .unwrap();
            actual.insert(rel, (7, target));
        } else {
            let mut content = Vec::new();
            fsys.open(&path).unwrap().read_to_end(&mut content).unwrap();
            actual.insert(rel, (1, content));
        }
    }

    assert_eq!(actual, expected);
}

#[test]
fn roundtrip_direct_lookup_reaches_every_entry() {
    let temp = TempDir::new();
    create_fixture(&temp.0);
    let image = build_fixture_image(&temp.0);
    let fsys = EroFS::new(SliceImage::new(&image)).unwrap();

    // "!leading" sorts before "." and leads the root's first dirent block.
    let mut content = Vec::new();
    fsys.open("/!leading")
        .unwrap()
        .read_to_end(&mut content)
        .unwrap();
    assert_eq!(content, b"bang\n");

    // Entries at the head of the root's later dirent blocks and of the
    // second block of "many" must be reachable by name.
    for i in 0..200 {
        let mut content = Vec::new();
        fsys.open(format!("/many/file-{i:04}"))
            .unwrap()
            .read_to_end(&mut content)
            .unwrap();
        assert_eq!(content, format!("content-{i}\n").into_bytes());
    }

    assert!(fsys.open("/many/file-0200").is_err());
    assert!(fsys.open("/sub/nope").is_err());
}

#[test]
fn roundtrip_preserves_metadata() {
    let temp = TempDir::new();
    create_fixture(&temp.0);
    let image = build_fixture_image(&temp.0);
    let fsys = EroFS::new(SliceImage::new(&image)).unwrap();

    let host = fs::metadata(temp.0.join("hello.txt")).unwrap();
    let entry = fsys
        .read_dir("/")
        .unwrap()
        .find_map(|e| {
            let e = e.unwrap();
            (e.dir_entry.file_name() == "hello.txt").then_some(e.inode)
        })
        .unwrap();
    assert_eq!(entry.uid(), host.uid());
    assert_eq!(entry.gid(), host.gid());
    assert_eq!(
        entry.permissions().mode() & 0o7777,
        host.permissions().mode() & 0o7777
    );
    // fixed_time drives every mtime.
    assert_eq!(
        entry.modified(),
        Some(UNIX_EPOCH + Duration::from_secs(FIXED_TIME))
    );

    // Directory nlink: 2 + number of subdirectories.
    let sub = fsys
        .read_dir("/")
        .unwrap()
        .find_map(|e| {
            let e = e.unwrap();
            (e.dir_entry.file_name() == "sub").then_some(e.inode)
        })
        .unwrap();
    assert_eq!(sub.nlink(), 3); // ".", "..", "deep"
}

#[test]
fn fixed_time_makes_builds_reproducible() {
    let temp = TempDir::new();
    create_fixture(&temp.0);
    let first = build_fixture_image(&temp.0);
    let second = build_fixture_image(&temp.0);
    assert_eq!(first, second);
}

#[test]
fn build_rejects_non_directory_root() {
    let temp = TempDir::new();
    let file = temp.0.join("file");
    fs::write(&file, b"x").unwrap();
    assert!(ImageBuilder::new().build_from_dir(&file).is_err());
}

#[test]
fn build_rejects_special_files() {
    let temp = TempDir::new();
    fs::write(temp.0.join("ok"), b"x").unwrap();
    let status = Command::new("mkfifo")
        .arg(temp.0.join("pipe"))
        .status()
        .unwrap();
    assert!(status.success());
    let err = ImageBuilder::new().build_from_dir(&temp.0).unwrap_err();
    assert!(err.to_string().contains("unsupported file type"));
}
