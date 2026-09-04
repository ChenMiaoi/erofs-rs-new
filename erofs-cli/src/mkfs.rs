use anyhow::{Context, Result};
use clap::Args;
use erofs_rs::builder::ImageBuilder;

#[derive(Args, Debug)]
pub struct MkfsArgs {
    /// Host directory to pack into the image.
    path: String,
    /// Output image path.
    #[clap(short, long)]
    output: String,
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
    let mut builder = ImageBuilder::new();
    if let Some(name) = &args.volume_name {
        builder = builder.volume_name(name)?;
    }
    if let Some(uuid) = args.uuid {
        builder = builder.uuid(uuid);
    }
    if let Some(secs) = args.fixed_time {
        builder = builder.fixed_time(secs);
    }

    let image = builder
        .build_from_dir(&args.path)
        .with_context(|| format!("failed to build image from {}", args.path))?;
    std::fs::write(&args.output, &image)
        .with_context(|| format!("failed to write {}", args.output))?;
    println!(
        "wrote {}: {} bytes ({} blocks)",
        args.output,
        image.len(),
        image.len() / 4096
    );
    Ok(())
}
