# erofs-rs

A pure Rust reader and inspection toolkit for [EROFS](https://docs.kernel.org/filesystems/erofs.html) images. The project focuses on checked on-disk parsing, read-only filesystem access, and deterministic malformed-image testing. It is not a Rust reimplementation of [erofs-utils](https://github.com/erofs/erofs-utils).

## Features

- `no_std` EROFS format primitives with checked image offsets
- Synchronous and asynchronous filesystem readers
- mmap, borrowed-slice, and optional OpenDAL backends
- Directory traversal and file reads for supported layouts
- Schema-backed field location with provenance and structured errors
- Deterministic mutation, replay, oracle, campaign, and minimization tooling

## Repository layout

- `erofs-format`: `no_std` on-disk decoding, schema metadata, and the field locator.
- `erofs`: the standard-library filesystem reader.
- `erofs-lab`: deterministic mutation, corpus, oracle, and minimization library.
- `erofs-cli`: inspection, conversion, mutation, replay, oracle, and campaign commands.
- `scripts/` and `Makefile`: the pinned Linux/QEMU workflow used for boot and fuzzing.

The workspace requires Rust 1.89 or newer. `vendor/linux` and
`vendor/erofs-utils` are git submodules used by the boot and fuzzing workflow.

## Library usage

### High-level reader

```rust
use std::io::Read;
use erofs_rs::{EroFS, backend::MmapImage};

fn main() -> erofs_rs::Result<()> {
    // SAFETY: the image must not be modified while it is mapped.
    let image = unsafe { MmapImage::new_from_path("system.erofs")? };
    let fs = EroFS::new(image)?;

    let mut file = fs.open("/etc/os-release")?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    for entry in fs.read_dir("/usr/bin")? {
        println!("{}", entry?.dir_entry.file_name());
    }
    Ok(())
}
```

### Low-level `no_std` format primitives

The high-level reader is `std`-only. Use `erofs-format` for OS-independent
on-disk decoding and checked image offsets.

```rust
use erofs_format::{ReadAt, SliceReader, Span, primary_inode_offset};

let image = SliceReader::new(include_bytes!("system.erofs"));
let inode_offset = primary_inode_offset(1, 12, 36)?;
let mut inode_header = [0; 2];
image.read_exact_at(inode_offset, &mut inode_header)?;
assert!(Span::new(inode_offset, 2)?.is_within(image.len()));
# Ok::<(), erofs_format::Error>(())
```

## Feature flags

```toml
[dependencies]
erofs-rs = "0.2.1"
erofs-format = "0.1.0"
```

Enable OpenDAL-backed asynchronous I/O when needed:

```toml
[dependencies]
erofs-rs = { version = "0.2.1", features = ["opendal"] }
```

## CLI

Build the CLI with `cargo build -p erofs-cli`. The available top-level
commands are `dump`, `inspect`, `convert`, `field`, `inject`, `replay`,
`oracle`, and `campaign`. Each command provides detailed help with `--help`.

```bash
# Inspect a local image.
erofs-cli dump image.erofs
erofs-cli inspect -i image.erofs ls /
erofs-cli inspect -i image.erofs cat /etc/os-release

# Convert a supported image tree to tar.
erofs-cli convert image.erofs --output out.tar

# List and locate schema fields.
erofs-cli field list --schema
erofs-cli field locate image.erofs --object inode --space primary --nid 36 \
  --field erofs.inode.compact.i_format --json
```

HTTP images are supported by the CLI commands that use the OpenDAL backend:

```bash
erofs-cli dump https://example.com/images/system.erofs
erofs-cli inspect -i https://example.com/images/system.erofs ls /
```

### Mutation and replay

Mutation commands resolve symbolic fields against an immutable baseline and
publish content-addressed samples. Replay uses the recorded manifest rather
than re-resolving the current locator.

```bash
erofs-cli inject set image.erofs --output-dir corpus \
  --object superblock --field erofs.superblock.fixed_nsec --value 1 \
  --integrity recalculate

erofs-cli replay corpus/samples/sha256/HASH/sample.json \
  --parent image.erofs --output-dir replayed-corpus
```

### Oracle and campaigns

Oracle profiles run in separate processes with resource limits and publish
immutable run records. Campaigns generate deterministic recipes, materialize
samples, track novelty, and optionally escalate through Rust, fsck, and Linux
oracles.

```bash
erofs-cli oracle run corpus/samples/sha256/HASH/sample.json \
  --profile rust-full

erofs-cli campaign run image.erofs --output-dir corpus --seed 17 \
  --field erofs.superblock.magic \
  --field erofs.superblock.fixed_nsec \
  --max-samples 64 --max-mutations 4 --max-oracle-runs 64 \
  --funnel novelty --integrity preserve

erofs-cli campaign minimize image.erofs --output-dir corpus \
  --recipe corpus/campaigns/CAMPAIGN/recipe.json --case CASE_ID \
  --profile rust-full --signature rust:superblock_parse --confirmations 2
```

Use `--no-tui` for script-friendly campaign output. The interactive dashboard
is enabled automatically when a terminal is available.

## Development and tests

```bash
git submodule update --init --depth 1
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Use `make deps-check` to check host tools. `make all` builds the pinned kernel,
initramfs, `mkfs.erofs`, and sample image; `make run` boots it in QEMU; `make
smoke` runs the bounded boot check. These targets require the vendor submodules
and system packages installed by `make apt-deps`.

## Metadata fuzzing

The long-running demo in `examples/metadata-fuzz.sh` runs deterministic
campaigns over superblock metadata. It stores recipes, reports, novelty state,
and content-addressed samples under the corpus directory.

```bash
make all
make fuzz --no-print-directory
make fuzz FUZZ_CORPUS=/srv/erofs-corpus \
  FUZZ_ARGS='--cases 10 --funnel all --no-tui'
```

The Makefile defaults to `build/rootfs.erofs` and
`build/metadata-fuzz-corpus`. Run `examples/metadata-fuzz.sh --help` for all
campaign bounds and workspace options. Use `--funnel materialize-only` when
oracle execution is not required.

## Supported layouts and limitations

Implemented in the high-level reader:

- Superblock, inode, and dirent parsing
- Flat plain and flat inline layouts
- Chunk-based layout without chunk indexes
- Synchronous and asynchronous file reads
- Directory walking and bounded traversal
- Tar conversion with unsafe metadata checks

Known limitations:

- Compressed file data is not decoded by the high-level reader.
- Chunk-based layouts using chunk indexes are not supported.
- Extended-attribute data access is not exposed by the high-level reader.
- Image creation is provided by the pinned `mkfs.erofs` workflow, not a Rust API.

Unsupported layouts are rejected rather than partially decoded. The schema
locator covers a broader ABI metadata surface than the high-level reader and
does not imply support for every layout.

## Coverage

```bash
cargo install cargo-llvm-cov --locked
make coverage
```

The report is written to `target/lcov.info`. CI uploads the same report as the
`lcov` artifact and does not impose a line-coverage threshold.

## License

MIT OR Apache-2.0
