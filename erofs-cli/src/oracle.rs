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
pub enum Profile {
    RustFull,
    FsckFull,
    FsckNoSbcrc,
    LinuxKasan,
}

impl From<Profile> for OracleProfile {
    fn from(value: Profile) -> Self {
        match value {
            Profile::RustFull => Self::RustFull,
            Profile::FsckFull => Self::FsckFull,
            Profile::FsckNoSbcrc => Self::FsckNoSbcrc,
            Profile::LinuxKasan => Self::LinuxKasan,
        }
    }
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

pub fn oracle_paths(workspace: &std::path::Path) -> Result<OraclePaths> {
    let workspace = workspace
        .canonicalize()
        .with_context(|| format!("failed to canonicalize workspace {}", workspace.display()))?;
    let current = env::current_exe()?;
    let reader_oracle = current.with_file_name("erofs-reader-oracle");
    // The reader oracle is a separate bin target of erofs-lab; dependency
    // bins are never built, so a plain `cargo build -p erofs-cli` leaves it
    // missing. Fail fast here rather than recording a harness error for
    // every RustFull run.
    if !is_executable(&reader_oracle) {
        anyhow::bail!(
            "reader oracle binary is missing or not executable: {}\n\
             build it with: cargo build -p erofs-lab",
            reader_oracle.display()
        );
    }
    Ok(OraclePaths {
        reader_oracle,
        fsck: workspace.join("build/erofs-utils/fsck/fsck.erofs"),
        qemu: which("qemu-system-x86_64")?,
        kernel: workspace.join("build/linux/arch/x86/boot/bzImage"),
        initramfs: workspace.join("build/initramfs.cpio.gz"),
        kernel_config: workspace.join("build/linux/.config"),
    })
}

fn run(args: RunArgs) -> Result<()> {
    let profile = OracleProfile::from(args.profile);
    let paths = oracle_paths(&args.workspace)?;
    let limits = run_limits(profile, args.timeout_ms);
    let published = run_oracle(&args.manifest, profile, &paths, limits)?;
    println!("status: {:?}", published.result.status);
    println!("phase: {:?}", published.result.phase);
    println!("signature: {}", published.result.signature);
    println!("record: {}", published.record.display());
    println!("stdout: {}", published.stdout.display());
    println!("stderr: {}", published.stderr.display());
    Ok(())
}

/// Resource limits for one profile: the KASAN guest boot relaxation always
/// applies, while `--timeout-ms` only overrides the timeout value.
fn run_limits(profile: OracleProfile, timeout_ms: Option<u64>) -> ResourceLimits {
    let mut limits = ResourceLimits::default();
    if profile == OracleProfile::LinuxKasan {
        limits.timeout_ms = 80_000;
        limits.cpu_seconds = 80;
        limits.address_space_bytes = 3 << 30;
        limits.processes = 64;
        limits.output_bytes = 8 << 20;
    }
    if let Some(timeout) = timeout_ms {
        limits.timeout_ms = timeout;
    }
    limits
}

fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.is_file()
        && path
            .metadata()
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

fn which(name: &str) -> Result<PathBuf> {
    let path = env::var_os("PATH").context("PATH is not set")?;
    env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .with_context(|| format!("{name} was not found in PATH"))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn kasan_relaxation_applies_without_timeout_override() {
        let limits = run_limits(OracleProfile::LinuxKasan, None);
        assert_eq!(limits.timeout_ms, 80_000);
        assert_eq!(limits.cpu_seconds, 80);
        assert_eq!(limits.address_space_bytes, 3 << 30);
        assert_eq!(limits.processes, 64);
        assert_eq!(limits.output_bytes, 8 << 20);
    }

    #[test]
    fn timeout_override_keeps_kasan_relaxation() {
        let limits = run_limits(OracleProfile::LinuxKasan, Some(5_000));
        assert_eq!(limits.timeout_ms, 5_000);
        assert_eq!(limits.cpu_seconds, 80);
        assert_eq!(limits.address_space_bytes, 3 << 30);
        assert_eq!(limits.processes, 64);
        assert_eq!(limits.output_bytes, 8 << 20);
    }

    #[test]
    fn timeout_override_only_changes_timeout_for_other_profiles() {
        let default = ResourceLimits::default();
        let limits = run_limits(OracleProfile::RustFull, Some(5_000));
        assert_eq!(limits.timeout_ms, 5_000);
        assert_eq!(limits.cpu_seconds, default.cpu_seconds);
        assert_eq!(limits.address_space_bytes, default.address_space_bytes);
        assert_eq!(limits.processes, default.processes);
        assert_eq!(limits.output_bytes, default.output_bytes);
    }

    #[test]
    fn reader_oracle_preflight_requires_an_executable_file() {
        let unique = format!("erofs-cli-oracle-test-{}", std::process::id());
        let path = env::temp_dir().join(unique);
        assert!(!is_executable(&path));
        fs::write(&path, b"#!/bin/sh\n").unwrap();
        assert!(!is_executable(&path));
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).unwrap();
        }
        assert!(is_executable(&path));
        fs::remove_file(&path).unwrap();
    }
}
