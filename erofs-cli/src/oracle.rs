use std::{env, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use erofs_lab::oracle::{OraclePaths, OracleProfile, ResourceLimits, run_oracle};

#[derive(Args, Debug)]
pub struct OracleArgs {
    #[command(subcommand)]
    command: OracleCommand,
}

#[derive(Subcommand, Debug)]
enum OracleCommand {
    /// Run one fixed oracle profile against an immutable sample manifest.
    Run(RunArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Profile {
    RustFull,
    FsckFull,
    FsckNoSbcrc,
    LinuxKasan,
}

#[derive(Args, Debug)]
struct RunArgs {
    /// Immutable sample manifest.
    manifest: PathBuf,
    #[arg(long, value_enum)]
    profile: Profile,
    /// Wall-clock timeout in milliseconds.
    #[arg(long)]
    timeout_ms: Option<u64>,
    /// Workspace root containing `build/` and `vendor/`.
    #[arg(long, default_value = ".")]
    workspace: PathBuf,
}

pub fn oracle(args: OracleArgs) -> Result<()> {
    match args.command {
        OracleCommand::Run(args) => run(args),
    }
}

fn run(args: RunArgs) -> Result<()> {
    let profile = match args.profile {
        Profile::RustFull => OracleProfile::RustFull,
        Profile::FsckFull => OracleProfile::FsckFull,
        Profile::FsckNoSbcrc => OracleProfile::FsckNoSbcrc,
        Profile::LinuxKasan => OracleProfile::LinuxKasan,
    };
    let workspace = args.workspace.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize workspace {}",
            args.workspace.display()
        )
    })?;
    let current = env::current_exe()?;
    let reader_oracle = current.with_file_name("erofs-reader-oracle");
    let qemu = which("qemu-system-x86_64")?;
    let paths = OraclePaths {
        reader_oracle,
        fsck: workspace.join("build/erofs-utils/fsck/fsck.erofs"),
        qemu,
        kernel: workspace.join("build/linux/arch/x86/boot/bzImage"),
        initramfs: workspace.join("build/initramfs.cpio.gz"),
        kernel_config: workspace.join("build/linux/.config"),
    };
    let mut limits = ResourceLimits::default();
    if let Some(timeout) = args.timeout_ms {
        limits.timeout_ms = timeout;
    }
    if profile == OracleProfile::LinuxKasan && args.timeout_ms.is_none() {
        limits.timeout_ms = 80_000;
        limits.cpu_seconds = 80;
        limits.address_space_bytes = 3 << 30;
        limits.processes = 64;
        limits.output_bytes = 8 << 20;
    }
    let published = run_oracle(&args.manifest, profile, &paths, limits)?;
    println!("status: {:?}", published.result.status);
    println!("phase: {:?}", published.result.phase);
    println!("signature: {}", published.result.signature);
    println!("record: {}", published.record.display());
    println!("stdout: {}", published.stdout.display());
    println!("stderr: {}", published.stderr.display());
    Ok(())
}

fn which(name: &str) -> Result<PathBuf> {
    let path = env::var_os("PATH").context("PATH is not set")?;
    env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .with_context(|| format!("{name} was not found in PATH"))
}
