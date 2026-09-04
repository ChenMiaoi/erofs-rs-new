use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use clap::Args;
use erofs_rs::builder::ImageBuilder;

const HELLO_SOURCE: &str = "hello";
const HELLO_OUTPUT: &str = "hello.erofs";
const HELLO_VOLUME_NAME: &str = "hello-demo";
const HELLO_FIXED_TIME: u64 = 1_700_000_000;
const HELLO_UUID: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
];

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Args, Debug)]
pub struct MkfsArgs {
    /// Host directory to pack, or `hello` for a built-in demo image.
    path: String,
    /// Output image path (`hello.erofs` by default for the hello demo).
    #[clap(short, long)]
    output: Option<String>,
    /// Volume name stored in the superblock (at most 16 bytes).
    #[clap(long)]
    volume_name: Option<String>,
    /// UUID stored in the superblock (all zero by default).
    #[clap(long, value_parser = parse_uuid)]
    uuid: Option<[u8; 16]>,
    /// Fix all inode mtimes and the build time to these seconds since the
    /// epoch, making the output byte-for-byte reproducible.
    #[clap(long)]
    fixed_time: Option<u64>,
}

fn parse_uuid(s: &str) -> std::result::Result<[u8; 16], uuid::Error> {
    uuid::Uuid::parse_str(s).map(|u| *u.as_bytes())
}

pub fn mkfs(args: MkfsArgs) -> Result<()> {
    let hello = args.path == HELLO_SOURCE;
    let output = match (&args.output, hello) {
        (Some(output), _) => output.as_str(),
        (None, true) => HELLO_OUTPUT,
        (None, false) => bail!("--output is required when packing a host directory"),
    };

    let mut builder = ImageBuilder::new();
    if let Some(name) = args
        .volume_name
        .as_deref()
        .or_else(|| hello.then_some(HELLO_VOLUME_NAME))
    {
        builder = builder.volume_name(name)?;
    }
    if let Some(uuid) = args.uuid.or_else(|| hello.then_some(HELLO_UUID)) {
        builder = builder.uuid(uuid);
    }
    if let Some(secs) = args
        .fixed_time
        .or_else(|| hello.then_some(HELLO_FIXED_TIME))
    {
        builder = builder.fixed_time(secs);
    }

    let image = if hello {
        build_hello_image(&builder)?
    } else {
        builder
            .build_from_dir(&args.path)
            .with_context(|| format!("failed to build image from {}", args.path))?
    };
    fs::write(output, &image).with_context(|| format!("failed to write {output}"))?;
    println!(
        "wrote {}: {} bytes ({} blocks)",
        output,
        image.len(),
        image.len() / 4096
    );
    if hello {
        println!("demo contents: /hello.txt, /bin/hello, /etc, /data, /links");
    }
    Ok(())
}

fn build_hello_image(builder: &ImageBuilder) -> Result<Vec<u8>> {
    let tree = DemoTree::create()?;
    builder
        .build_from_dir(&tree.root)
        .context("failed to build built-in hello image")
}

/// A disposable host tree used as input to the directory-based image builder.
struct DemoTree {
    root: PathBuf,
}

impl DemoTree {
    fn create() -> Result<Self> {
        let root = create_temp_dir()?;
        let tree = Self { root };
        tree.populate()?;
        Ok(tree)
    }

    fn populate(&self) -> Result<()> {
        for directory in ["bin", "etc", "data", "links", "usr/share/doc/hello"] {
            fs::create_dir_all(self.root.join(directory))?;
        }

        self.write(
            "hello.txt",
            b"Hello from an EROFS demo image!\n\
              \n\
              Try: erofs-cli inspect -i hello.erofs ls /\n\
              And: erofs-cli inspect -i hello.erofs cat /hello.txt\n",
        )?;
        self.write(
            "etc/os-release",
            b"NAME=\"EROFS Demo\"\nID=erofs-demo\nVERSION_ID=\"1\"\n",
        )?;
        self.write("etc/hostname", b"erofs-demo\n")?;
        self.write(
            "bin/hello",
            b"#!/bin/sh\nprintf '%s\\n' 'hello from EROFS'\n",
        )?;
        fs::set_permissions(
            self.root.join("bin/hello"),
            fs::Permissions::from_mode(0o755),
        )?;
        self.write("data/empty", b"")?;
        self.write("data/bytes-0-to-255.bin", &(0u8..=255).collect::<Vec<_>>())?;
        self.write("data/one-block.bin", &vec![b'A'; 4096])?;
        self.write("data/multi-block.bin", &vec![b'B'; 8193])?;
        self.write(
            "usr/share/doc/hello/README.txt",
            b"This nested file exercises directory walking.\n",
        )?;
        self.write("usr/share/doc/hello/unicode-你好.txt", b"UTF-8 filename\n")?;

        symlink("../hello.txt", self.root.join("links/hello.txt"))?;
        symlink("../bin/hello", self.root.join("links/hello-command"))?;
        Ok(())
    }

    fn write(&self, path: impl AsRef<Path>, contents: &[u8]) -> Result<()> {
        fs::write(self.root.join(path), contents)?;
        Ok(())
    }
}

impl Drop for DemoTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn create_temp_dir() -> Result<PathBuf> {
    let base = std::env::temp_dir();
    for _ in 0..100 {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!("erofs-cli-hello-{}-{id}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("failed to create hello demo directory"),
        }
    }
    bail!("failed to allocate a unique hello demo directory")
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use erofs_rs::{EroFS, backend::SliceImage};

    use super::*;

    fn hello_builder() -> ImageBuilder {
        ImageBuilder::new()
            .volume_name(HELLO_VOLUME_NAME)
            .unwrap()
            .uuid(HELLO_UUID)
            .fixed_time(HELLO_FIXED_TIME)
    }

    #[test]
    fn hello_image_is_reproducible_and_readable() {
        let first = build_hello_image(&hello_builder()).unwrap();
        let second = build_hello_image(&hello_builder()).unwrap();
        assert_eq!(first, second);

        let filesystem = EroFS::new(SliceImage::new(&first)).unwrap();
        assert_eq!(filesystem.super_block().uuid, HELLO_UUID);
        assert_eq!(filesystem.super_block().build_time, HELLO_FIXED_TIME);
        assert_eq!(
            &filesystem.super_block().volume_name[..HELLO_VOLUME_NAME.len()],
            HELLO_VOLUME_NAME.as_bytes()
        );

        let mut hello = String::new();
        filesystem
            .open("/hello.txt")
            .unwrap()
            .read_to_string(&mut hello)
            .unwrap();
        assert!(hello.contains("Hello from an EROFS demo image!"));

        let mut binary = Vec::new();
        filesystem
            .open("/data/bytes-0-to-255.bin")
            .unwrap()
            .read_to_end(&mut binary)
            .unwrap();
        assert_eq!(binary, (0u8..=255).collect::<Vec<_>>());

        assert_eq!(
            filesystem.open("/data/multi-block.bin").unwrap().size(),
            8193
        );
    }
}
