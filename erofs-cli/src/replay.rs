use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use erofs_lab::replay;

#[derive(Args, Debug)]
pub struct ReplayArgs {
    /// Immutable sample manifest.
    manifest: PathBuf,
    /// Parent image whose identity must match the manifest.
    #[arg(long)]
    parent: PathBuf,
    /// Content-addressed corpus root.
    #[arg(long)]
    output_dir: PathBuf,
}

pub fn replay_sample(args: ReplayArgs) -> Result<()> {
    let sample = replay(&args.parent, &args.output_dir, &args.manifest)?;
    println!("sample: {}", sample.output_sha256);
    println!("image: {}", sample.image.display());
    println!("manifest: {}", sample.manifest.display());
    Ok(())
}
