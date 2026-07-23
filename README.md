# erofs-rs

A pure Rust library for reading [EROFS](https://docs.kernel.org/filesystems/erofs.html) (Enhanced Read-Only File System) images.

For implementation coverage, the pinned Linux EROFS disk ABI, and fuzzing and injection field registration, see the compiled schema exposed by `erofs-cli field list --schema`.

> **Note**: This library aims to provide essential parsing and inspection capabilities for common use cases, not a full reimplementation of [erofs-utils](https://github.com/erofs/erofs-utils).

## Features

- A dedicated `no_std` format crate for endian decoding and checked image offsets
- Zero-copy reader backends using mmap or borrowed byte slices
- Directory traversal and file reading
- Multiple data layouts: flat plain, flat inline, chunk-based

## Vendor Linux boot environment

The repository pins `vendor/linux` and `vendor/erofs-utils` submodules. Build a `mkfs.erofs` image and boot Linux under QEMU with:

```bash
git submodule update --init --depth 1
make all
make run
```

## Usage

### High-level reader

```rust
use std::io::Read;
use erofs_rs::{EroFS, backend::MmapImage};

fn main() -> erofs_rs::Result<()> {
    let image = MmapImage::new_from_path("system.erofs")?;
    let fs = EroFS::new(image)?;

    // Read file
    let mut file = fs.open("/etc/os-release")?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    // List directory
    for entry in fs.read_dir("/usr/bin")? {
        println!("{}", entry?.dir_entry.file_name());
    }

    Ok(())
}
```

### Low-level `no_std` format primitives

The high-level `erofs-rs` reader is intentionally `std`-only. OS-independent
on-disk decoding and checked `u64` image offsets live in the separate
`erofs-format` crate, which has no default features and forbids unsafe code.

```rust
use erofs_format::{ReadAt, SliceReader, Span, primary_inode_offset};

let image = SliceReader::new(include_bytes!("system.erofs"));
let inode_offset = primary_inode_offset(1, 12, 36)?;
let mut inode_header = [0; 2];
image.read_exact_at(inode_offset, &mut inode_header)?;
assert!(Span::new(inode_offset, 2)?.is_within(image.len()));
# Ok::<(), erofs_format::Error>(())
```

## Feature Flags

- `std` (default): Compatibility feature retained for existing 0.2.x dependents; the high-level reader is always std-only
- `opendal`: Enables async I/O via [Apache OpenDAL](https://opendal.apache.org/), supporting remote backends (HTTP, S3, etc.)

```toml
# High-level reader
[dependencies]
erofs-rs = "0.2.1"

# Async reader with OpenDAL
[dependencies]
erofs-rs = { version = "0.2.1", features = ["opendal"] }

# Low-level no_std format primitives
[dependencies]
erofs-format = "0.1.0"
```

## CLI

```bash
# Dump superblock info
erofs-cli dump image.erofs

# List directory
erofs-cli inspect -i image.erofs ls /

# Read file content
erofs-cli inspect -i image.erofs cat /etc/passwd

# Convert to tar
erofs-cli convert image.erofs -o out.tar

# Remote images via HTTP (async OpenDAL backend)
erofs-cli dump http://example.com/images/system.erofs
erofs-cli inspect -i http://example.com/images/system.erofs ls /
erofs-cli inspect -i http://example.com/images/system.erofs cat /etc/os-release
```

## Status

### Implemented

- [x] Superblock / inode / dirent parsing
- [x] Flat plain layout, including bounded multi-block reads
- [x] Flat inline layout, including exact-block-size files
- [x] Chunk-based layout (without chunk indexes)
- [x] Directory walk (`walk_dir`)
- [x] Convert to tar archive

### TODO

- [ ] Extended attributes
- [ ] Compressed data (lz4, lzma, deflate)
- [ ] Image building (`mkfs.erofs` equivalent)

## License

MIT OR Apache-2.0
