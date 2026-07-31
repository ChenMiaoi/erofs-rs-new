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

### Pinned ABI field locator

The `erofs-format` schema and locator are independent of the high-level reader.
They expose stable field IDs, checked absolute spans, raw/decoded values,
feature predicates, provenance, and structured failures for the M1 superblock,
primary inode, and flat-directory subset.

```bash
erofs-cli field list --schema
erofs-cli field locate image.erofs --object inode --space primary --nid 36 \
  --field erofs.inode.compact.i_format --json
erofs-cli field locate image.erofs --object dirent --nid 36 --block 0 --index 0 \
  --field erofs.dirent.nameoff --mode tolerant --json
```

### Deterministic mutation and replay

M2 resolves symbolic mutations against an immutable baseline, records exact
before/after patches, publishes samples by SHA-256, and replays manifests
without invoking the current locator. Canonical samples are read-only and live
under `samples/sha256/<output-sha256>`.

```bash
erofs-cli inject set image.erofs --output-dir corpus \
  --object superblock --field erofs.superblock.fixed_nsec --value 1 \
  --integrity recalculate
erofs-cli inject bits image.erofs --output-dir corpus \
  --object superblock --field erofs.superblock.feature_compat --set 0x2
erofs-cli inject bytes image.erofs --output-dir corpus \
  --object superblock --field erofs.superblock.volume_name \
  --hex 65726f66732d6d75746174696f6e0000
erofs-cli inject raw image.erofs --output-dir corpus \
  --offset 0x428 --hex ff00aa55 --mode raw
erofs-cli inject truncate image.erofs --output-dir corpus \
  --length 3072 --mode raw
erofs-cli replay corpus/samples/sha256/HASH/sample.json \
  --parent image.erofs --output-dir replayed-corpus
```

### Independent oracle profiles

M3 runs each oracle in a separate process under a user and network namespace,
with CPU, address-space, file-size, process-count, wall-time, and log limits.
Results are immutable records under `runs/<sample-sha256>/<profile>/` and never
modify `sample.json`.

```bash
erofs-cli oracle run corpus/samples/sha256/HASH/sample.json \
  --profile rust-full
erofs-cli oracle run corpus/samples/sha256/HASH/sample.json \
  --profile fsck-full
erofs-cli oracle run corpus/samples/sha256/HASH/sample.json \
  --profile fsck-no-sbcrc
erofs-cli oracle run corpus/samples/sha256/HASH/sample.json \
  --profile linux-kasan --timeout-ms 80000
```

Profiles record complete argv, fixed environment, resource limits, binary and
kernel/config/initramfs hashes, exit status, signal, wall time, bounded logs,
classifier rule, phase, status, and stable signature.

### Deterministic campaigns and minimization

M4 records `chacha12/v1` recipes, deterministic field enumeration, dependency-aware
combinations, byte/plan/result novelty identities, and a Rust → fsck → Linux
escalation funnel with explicit sample, mutation, image, oracle, and wall-time
budgets.

```bash
erofs-cli campaign run image.erofs --output-dir corpus --seed 17 \
  --field erofs.superblock.magic \
  --field erofs.superblock.fixed_nsec \
  --max-samples 64 --max-mutations 4 --max-oracle-runs 64 \
  --funnel novelty --integrity preserve

erofs-cli campaign minimize image.erofs --output-dir corpus \
  --recipe corpus/campaigns/CAMPAIGN/recipe.json --case CASE_ID \
  --profile rust-full --signature rust:superblock_parse \
  --confirmations 2
```

Minimization removes intent groups first, then shrinks field values, bit sets,
raw patches, and truncate deltas. Every candidate regenerates integrity repair
and must reproduce the same signature repeatedly in the same profile.

### Long-running metadata fuzzing demo

`examples/metadata-fuzz.sh` repeatedly launches deterministic campaigns over
superblock metadata: identity, feature flags, sizing, metadata/xattr placement,
and extension fields. Rounds share a content-addressed corpus and novelty index;
every generated mutation remains reproducible through its recorded recipe and
sample manifest. The campaign dashboard is enabled automatically in a terminal.

```bash
# Build the reader, fsck, kernel, and oracle artifacts for the novelty funnel.
make all

# Fuzz for one day into a resumable corpus.
make fuzz

# Seven-day run with a larger deterministic batch and full oracle escalation.
make fuzz FUZZ_CORPUS=/srv/erofs-corpus \
  FUZZ_ARGS='--duration-seconds 604800 --samples-per-round 8192 --funnel all'

# Exactly ten generated cases, independent of their total execution time.
make fuzz FUZZ_ARGS='--cases 10 --funnel all'
```

The Makefile entry point uses `build/rootfs.erofs` and
`build/metadata-fuzz-corpus` by default. Override `FUZZ_IMAGE` or `FUZZ_CORPUS`,
or invoke `examples/metadata-fuzz.sh` directly for the full interface.

`make fuzz` reuses `build/linux/arch/x86/boot/bzImage`, `build/initramfs.cpio.gz`,
`build/erofs-utils`, and `build/rootfs.erofs` when present. `make fuzz-prereqs`
performs the same incremental check explicitly; it rebuilds the kernel only when
its source or configuration has changed.

Use `--funnel materialize-only` for high-throughput mutation generation without
oracle execution, or `--no-tui` for logs and CI. Run the script with `--help`
for all bounds and workspace options.

## Coverage

Install [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov), then generate an LCOV report for the full workspace and enabled features:

```bash
cargo install cargo-llvm-cov --locked
make coverage
```

The report is written to `target/lcov.info`. CI uploads the same report as the `lcov` artifact; it records coverage only and does not impose a line-coverage threshold. Metadata acceptance is enforced separately by locator schema-matrix tests.

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
