//! Independent oracle subprocesses, classification, and immutable run records.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, SampleManifest};

const RUN_SCHEMA: &str = "erofs-oracle-run/v1";
const CLASSIFIER_VERSION: &str = "erofs-oracle-classifier/v1";
const EROFS_UTILS_COMMIT: &str = "30711d4b2e234fe3e8aaeb779ade4cb609b0d920";
const LINUX_COMMIT: &str = "980ab36ae5972c83f683b939e50c469c4947229e";
const DANGEROUS: &[(&str, &str)] = &[
    ("kasan", "kasan"),
    ("kmsan", "kmsan"),
    ("ubsan", "ubsan"),
    ("kernel bug", "kernel_bug"),
    ("bug:", "kernel_bug"),
    ("oops:", "oops"),
    ("kernel panic", "kernel_panic"),
    ("general protection fault", "general_protection_fault"),
    ("kernel null pointer dereference", "null_pointer"),
    ("invalid opcode", "invalid_opcode"),
];

/// Stable oracle profile names.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OracleProfile {
    RustFull,
    FsckFull,
    FsckNoSbcrc,
    LinuxKasan,
}

impl OracleProfile {
    pub const fn name(self) -> &'static str {
        match self {
            Self::RustFull => "rust-full",
            Self::FsckFull => "fsck-full",
            Self::FsckNoSbcrc => "fsck-no-sbcrc",
            Self::LinuxKasan => "linux-kasan",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleStatus {
    Accepted,
    Rejected,
    Crashed,
    TimedOut,
    ResourceExhausted,
    Unsupported,
    HarnessError,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OraclePhase {
    Open,
    Superblock,
    Mount,
    Inode,
    Lookup,
    Readdir,
    Traverse,
    ReadData,
    MapData,
    Decompress,
    Xattr,
    Unmount,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub timeout_ms: u64,
    pub cpu_seconds: u64,
    pub address_space_bytes: u64,
    pub file_bytes: u64,
    pub processes: u64,
    pub output_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000,
            cpu_seconds: 20,
            address_space_bytes: 1 << 30,
            file_bytes: 1 << 30,
            processes: 32,
            output_bytes: 1 << 20,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OraclePaths {
    pub reader_oracle: PathBuf,
    pub fsck: PathBuf,
    pub qemu: PathBuf,
    pub kernel: PathBuf,
    pub initramfs: PathBuf,
    pub kernel_config: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecord {
    pub sha256: String,
    pub bytes: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OracleIdentity {
    pub kind: String,
    pub source_commit: Option<String>,
    pub binary: String,
    pub binary_sha256: String,
    pub config_sha256: Option<String>,
    pub kernel_sha256: Option<String>,
    pub initramfs_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRecord {
    pub argv: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub working_directory: String,
    pub sandbox: String,
    pub network: String,
    pub limits: ResourceLimits,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub wall_ms: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OracleResult {
    pub status: OracleStatus,
    pub phase: OraclePhase,
    pub signature: String,
    pub classifier: String,
    pub matched_rule: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OracleRunRecord {
    pub schema: String,
    pub sample_sha256: String,
    pub profile: OracleProfile,
    pub oracle: OracleIdentity,
    pub execution: ExecutionRecord,
    pub result: OracleResult,
    pub stdout: ArtifactRecord,
    pub stderr: ArtifactRecord,
}

#[derive(Clone, Debug)]
pub struct PublishedRun {
    pub record: PathBuf,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
    pub result: OracleResult,
}

#[derive(Debug)]
struct ProcessOutput {
    status: Option<std::process::ExitStatus>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    wall: Duration,
    timed_out: bool,
    truncated_stdout: bool,
    truncated_stderr: bool,
}

#[derive(Debug)]
struct CapturedLog {
    bytes: Vec<u8>,
    truncated: bool,
}

/// Executes one oracle profile and appends an immutable run record.
pub fn run_oracle(
    manifest_path: &Path,
    profile: OracleProfile,
    paths: &OraclePaths,
    limits: ResourceLimits,
) -> Result<PublishedRun, Error> {
    let manifest: SampleManifest = serde_json::from_slice(&fs::read(manifest_path)?)?;
    let sample = manifest_path
        .parent()
        .ok_or(Error::InvalidInput)?
        .join("image.erofs");
    if sha256_file(&sample)? != manifest.output.sha256 {
        return Err(Error::OutputIdentity);
    }
    let run_root = manifest_path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or(Error::InvalidInput)?
        .join("runs")
        .join(&manifest.output.sha256)
        .join(profile.name());
    fs::create_dir_all(&run_root)?;
    let attempt = format!(
        "{}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::InvalidInput)?
            .as_nanos(),
        std::process::id()
    );
    let stage = run_root.join(format!(".{attempt}.stage"));
    fs::create_dir(&stage)?;
    let extraction = stage.join("extract");
    fs::create_dir(&extraction)?;

    let (identity, argv, sandbox, output, result) = match profile {
        OracleProfile::RustFull => {
            let argv = vec![
                paths.reader_oracle.display().to_string(),
                sample.display().to_string(),
            ];
            let output = run_sandboxed(&argv, &stage, &limits, false)?;
            let result = classify_rust(&output);
            (
                identity("rust-reader", None, &paths.reader_oracle, None, None, None)?,
                argv,
                "unshare-user-net+rlimit".into(),
                output,
                result,
            )
        }
        OracleProfile::FsckFull | OracleProfile::FsckNoSbcrc => {
            let mut argv = vec![
                paths.fsck.display().to_string(),
                format!("--extract={}", extraction.display()),
            ];
            if profile == OracleProfile::FsckNoSbcrc {
                argv.push("--no-sbcrc".into());
            }
            argv.push(sample.display().to_string());
            let output = run_sandboxed(&argv, &stage, &limits, false)?;
            let result = classify_fsck(&output);
            (
                identity(
                    "fsck.erofs",
                    Some(EROFS_UTILS_COMMIT),
                    &paths.fsck,
                    None,
                    None,
                    None,
                )?,
                argv,
                "unshare-user-net+rlimit+private-extract".into(),
                output,
                result,
            )
        }
        OracleProfile::LinuxKasan => {
            let argv = qemu_argv(paths, &sample);
            let output = run_sandboxed(&argv, &stage, &limits, true)?;
            let result = classify_qemu(&output);
            (
                identity(
                    "vendor-linux-qemu",
                    Some(LINUX_COMMIT),
                    &paths.qemu,
                    Some(&paths.kernel_config),
                    Some(&paths.kernel),
                    Some(&paths.initramfs),
                )?,
                argv,
                "unshare-user-net+rlimit+readonly-virtio".into(),
                output,
                result,
            )
        }
    };

    let stdout = artifact(&output.stdout, output.truncated_stdout);
    let stderr = artifact(&output.stderr, output.truncated_stderr);
    let execution = ExecutionRecord {
        argv,
        environment: BTreeMap::from([("LC_ALL".into(), "C".into()), ("TZ".into(), "UTC".into())]),
        working_directory: stage.display().to_string(),
        sandbox,
        network: "new-network-namespace:no-interfaces".into(),
        limits,
        exit_code: output.status.and_then(|status| status.code()),
        signal: output.status.and_then(|status| status.signal()),
        wall_ms: output.wall.as_millis().to_string(),
    };
    let record = OracleRunRecord {
        schema: RUN_SCHEMA.into(),
        sample_sha256: manifest.output.sha256,
        profile,
        oracle: identity,
        execution,
        result: result.clone(),
        stdout,
        stderr,
    };
    let stdout_path = stage.join("stdout.log");
    let stderr_path = stage.join("stderr.log");
    let record_path = stage.join("run.json");
    write_synced(&stdout_path, &output.stdout)?;
    write_synced(&stderr_path, &output.stderr)?;
    let mut json = serde_json::to_vec(&record)?;
    json.push(b'\n');
    write_synced(&record_path, &json)?;
    File::open(&stage)?.sync_all()?;
    let final_dir = run_root.join(attempt);
    fs::rename(&stage, &final_dir)?;
    File::open(&run_root)?.sync_all()?;
    Ok(PublishedRun {
        record: final_dir.join("run.json"),
        stdout: final_dir.join("stdout.log"),
        stderr: final_dir.join("stderr.log"),
        result,
    })
}

fn run_sandboxed(
    argv: &[String],
    cwd: &Path,
    limits: &ResourceLimits,
    qemu: bool,
) -> Result<ProcessOutput, Error> {
    if argv.is_empty() || !Path::new(&argv[0]).is_file() {
        return Ok(harness_output("oracle binary is missing"));
    }
    let mut args = vec![
        "--user".into(),
        "--map-current-user".into(),
        "--net".into(),
        "--fork".into(),
        "--kill-child".into(),
        "prlimit".into(),
        format!("--cpu={}", limits.cpu_seconds),
        format!("--as={}", limits.address_space_bytes),
        format!("--fsize={}", limits.file_bytes),
        format!("--nproc={}", limits.processes),
        "--".into(),
    ];
    args.extend(argv.iter().cloned());
    let mut command = Command::new("unshare");
    command
        .args(&args)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let start = Instant::now();
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return Ok(harness_output(&format!("sandbox spawn failed: {error}"))),
    };
    let stdout = child.stdout.take().ok_or(Error::InvalidInput)?;
    let stderr = child.stderr.take().ok_or(Error::InvalidInput)?;
    let output_limit = limits.output_bytes;
    let stdout_thread = thread::spawn(move || capture_log(stdout, output_limit));
    let stderr_thread = thread::spawn(move || capture_log(stderr, output_limit));
    let deadline = start + Duration::from_millis(limits.timeout_ms);
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait()? {
            break (Some(status), false);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            break (Some(child.wait()?), true);
        }
        thread::sleep(Duration::from_millis(if qemu { 20 } else { 5 }));
    };
    let stdout = stdout_thread.join().map_err(|_| Error::InvalidInput)?;
    let stderr = stderr_thread.join().map_err(|_| Error::InvalidInput)?;
    Ok(ProcessOutput {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        wall: start.elapsed(),
        timed_out,
        truncated_stdout: stdout.truncated,
        truncated_stderr: stderr.truncated,
    })
}

fn qemu_argv(paths: &OraclePaths, sample: &Path) -> Vec<String> {
    vec![
        paths.qemu.display().to_string(),
        "-machine".into(),
        "accel=tcg".into(),
        "-cpu".into(),
        "max".into(),
        "-m".into(),
        "1024M".into(),
        "-smp".into(),
        "2".into(),
        "-nographic".into(),
        "-no-reboot".into(),
        "-nic".into(),
        "none".into(),
        "-kernel".into(),
        paths.kernel.display().to_string(),
        "-initrd".into(),
        paths.initramfs.display().to_string(),
        "-append".into(),
        "console=ttyS0 earlyprintk=serial panic=-1".into(),
        "-drive".into(),
        format!("file={},if=virtio,format=raw,readonly=on", sample.display()),
    ]
}

fn classify_rust(output: &ProcessOutput) -> OracleResult {
    if output.timed_out {
        return result(
            OracleStatus::TimedOut,
            OraclePhase::Unknown,
            "rust:timeout",
            Some("timeout"),
        );
    }
    if output.status.and_then(|status| status.signal()).is_some() {
        return result(
            OracleStatus::Crashed,
            OraclePhase::Unknown,
            "rust:signal",
            Some("signal"),
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    if text.lines().any(|line| {
        line.contains("\"phase\":\"complete\"") && line.contains("\"status\":\"accepted\"")
    }) {
        return result(
            OracleStatus::Accepted,
            OraclePhase::Traverse,
            "rust:accepted",
            Some("complete-marker"),
        );
    }
    if let Some(line) = text
        .lines()
        .rev()
        .find(|line| line.contains("\"status\":\"rejected\""))
    {
        return result(
            OracleStatus::Rejected,
            phase_from_text(line),
            &format!("rust:{}", class_from_json(line)),
            Some("rejected-event"),
        );
    }
    if output.status.is_some_and(|status| !status.success()) {
        return result(
            OracleStatus::HarnessError,
            OraclePhase::Unknown,
            "rust:unexpected-exit",
            Some("unexpected-exit"),
        );
    }
    result(
        OracleStatus::HarnessError,
        OraclePhase::Unknown,
        "rust:missing-marker",
        Some("missing-marker"),
    )
}

fn classify_fsck(output: &ProcessOutput) -> OracleResult {
    if output.timed_out {
        return result(
            OracleStatus::TimedOut,
            OraclePhase::Unknown,
            "fsck:timeout",
            Some("timeout"),
        );
    }
    if output.status.and_then(|status| status.signal()).is_some() {
        return result(
            OracleStatus::Crashed,
            OraclePhase::Unknown,
            "fsck:signal",
            Some("signal"),
        );
    }
    if output.status.is_some_and(|status| status.success()) {
        return result(
            OracleStatus::Accepted,
            OraclePhase::Traverse,
            "fsck:clean",
            Some("exit-zero"),
        );
    }
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .to_ascii_lowercase();
    if text.contains("unsupported") || text.contains("not supported") {
        return result(
            OracleStatus::Unsupported,
            OraclePhase::Unknown,
            "fsck:unsupported",
            Some("unsupported-diagnostic"),
        );
    }
    if text.contains("corrupt")
        || text.contains("invalid")
        || text.contains("cannot find valid")
        || text.contains("failed to read superblock")
        || text.contains("failed to verify")
        || text.contains("bad message")
    {
        return result(
            OracleStatus::Rejected,
            fsck_phase(&text),
            "fsck:corruption",
            Some("corruption-diagnostic"),
        );
    }
    result(
        OracleStatus::HarnessError,
        OraclePhase::Unknown,
        "fsck:unexpected-exit",
        Some("unexpected-exit"),
    )
}

fn classify_qemu(output: &ProcessOutput) -> OracleResult {
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let lower = text.to_ascii_lowercase();
    if let Some((_, signature)) = DANGEROUS
        .iter()
        .find(|(pattern, _)| lower.contains(pattern))
    {
        return result(
            OracleStatus::Crashed,
            OraclePhase::Unknown,
            &format!("linux:{signature}"),
            Some(signature),
        );
    }
    if lower.contains("status=resource_exhausted") {
        return result(
            OracleStatus::ResourceExhausted,
            phase_from_text(&lower),
            "linux:resource-exhausted",
            Some("guest-resource-marker"),
        );
    }
    if output.timed_out {
        return result(
            OracleStatus::TimedOut,
            OraclePhase::Unknown,
            "linux:timeout",
            Some("timeout"),
        );
    }
    if lower.contains("erofs_oracle phase=mount status=rejected") {
        return result(
            OracleStatus::Rejected,
            OraclePhase::Mount,
            "linux:mount-rejected",
            Some("mount-rejected-marker"),
        );
    }
    if lower.contains("erofs_oracle phase=complete status=accepted") {
        return result(
            OracleStatus::Accepted,
            OraclePhase::Traverse,
            "linux:accepted",
            Some("complete-marker"),
        );
    }
    if lower.contains("status=rejected") {
        return result(
            OracleStatus::Rejected,
            phase_from_text(&lower),
            "linux:traversal-rejected",
            Some("guest-rejected-marker"),
        );
    }
    if output.status.and_then(|status| status.signal()).is_some() {
        return result(
            OracleStatus::Crashed,
            OraclePhase::Unknown,
            "linux:qemu-signal",
            Some("qemu-signal"),
        );
    }
    result(
        OracleStatus::HarnessError,
        OraclePhase::Unknown,
        "linux:missing-marker",
        Some("missing-marker"),
    )
}

fn result(
    status: OracleStatus,
    phase: OraclePhase,
    signature: &str,
    rule: Option<&str>,
) -> OracleResult {
    OracleResult {
        status,
        phase,
        signature: signature.into(),
        classifier: CLASSIFIER_VERSION.into(),
        matched_rule: rule.map(Into::into),
    }
}

fn phase_from_text(text: &str) -> OraclePhase {
    for (needle, phase) in [
        ("read_data", OraclePhase::ReadData),
        ("decompress", OraclePhase::Decompress),
        ("map_data", OraclePhase::MapData),
        ("superblock", OraclePhase::Superblock),
        ("readdir", OraclePhase::Readdir),
        ("traverse", OraclePhase::Traverse),
        ("mount", OraclePhase::Mount),
        ("inode", OraclePhase::Inode),
        ("lookup", OraclePhase::Lookup),
        ("xattr", OraclePhase::Xattr),
        ("open", OraclePhase::Open),
    ] {
        if text.contains(needle) {
            return phase;
        }
    }
    OraclePhase::Unknown
}

fn fsck_phase(text: &str) -> OraclePhase {
    if text.contains("checksum") || text.contains("superblock") {
        OraclePhase::Superblock
    } else if text.contains("decompress") {
        OraclePhase::Decompress
    } else if text.contains("xattr") {
        OraclePhase::Xattr
    } else if text.contains("directory") {
        OraclePhase::Readdir
    } else {
        OraclePhase::Unknown
    }
}

fn class_from_json(line: &str) -> String {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|value| {
            value
                .get("error_class")
                .and_then(|value| value.as_str())
                .map(Into::into)
        })
        .unwrap_or_else(|| "rejected".into())
}

fn identity(
    kind: &str,
    commit: Option<&str>,
    binary: &Path,
    config: Option<&Path>,
    kernel: Option<&Path>,
    initramfs: Option<&Path>,
) -> Result<OracleIdentity, Error> {
    Ok(OracleIdentity {
        kind: kind.into(),
        source_commit: commit.map(Into::into),
        binary: binary.display().to_string(),
        binary_sha256: sha256_file(binary)?,
        config_sha256: config.map(sha256_file).transpose()?,
        kernel_sha256: kernel.map(sha256_file).transpose()?,
        initramfs_sha256: initramfs.map(sha256_file).transpose()?,
    })
}

fn artifact(bytes: &[u8], truncated: bool) -> ArtifactRecord {
    ArtifactRecord {
        sha256: sha256_bytes(bytes),
        bytes: bytes.len().to_string(),
        truncated,
    }
}
fn capture_log(mut reader: impl Read, limit: u64) -> CapturedLog {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut bytes = Vec::with_capacity(limit.min(8 * 1024));
    let mut buffer = [0; 8 * 1024];
    let mut truncated = false;
    while let Ok(read) = reader.read(&mut buffer) {
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(bytes.len());
        let retained = read.min(remaining);
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained != read;
    }
    CapturedLog { bytes, truncated }
}
fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn sha256_file(path: &Path) -> Result<String, Error> {
    Ok(sha256_bytes(&fs::read(path)?))
}
fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn harness_output(message: &str) -> ProcessOutput {
    ProcessOutput {
        status: None,
        stdout: Vec::new(),
        stderr: message.as_bytes().to_vec(),
        wall: Duration::ZERO,
        timed_out: false,
        truncated_stdout: false,
        truncated_stderr: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(stdout: &str, stderr: &str, code: i32, timed_out: bool) -> ProcessOutput {
        ProcessOutput {
            status: Some(std::process::ExitStatus::from_raw(code << 8)),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            wall: Duration::from_millis(1),
            timed_out,
            truncated_stdout: false,
            truncated_stderr: false,
        }
    }

    #[test]
    fn qemu_danger_after_acceptance_wins() {
        let result = classify_qemu(&output(
            "EROFS_ORACLE phase=complete status=accepted\nBUG: bad page",
            "",
            0,
            false,
        ));
        assert_eq!(result.status, OracleStatus::Crashed);
    }

    #[test]
    fn qemu_mount_rejection_is_not_harness_error() {
        let result = classify_qemu(&output(
            "EROFS_ORACLE phase=mount status=rejected errno=22",
            "",
            0,
            false,
        ));
        assert_eq!(
            (result.status, result.phase),
            (OracleStatus::Rejected, OraclePhase::Mount)
        );
    }

    #[test]
    fn fsck_superblock_rejection_is_format_rejection() {
        let result = classify_fsck(&output(
            "",
            "cannot find valid erofs superblock\nfailed to read superblock",
            1,
            false,
        ));
        assert_eq!(
            (result.status, result.phase),
            (OracleStatus::Rejected, OraclePhase::Superblock)
        );
    }

    #[test]
    fn qemu_resource_marker_has_priority_over_acceptance() {
        let result = classify_qemu(&output(
            "EROFS_ORACLE phase=read_data status=resource_exhausted reason=byte_limit\n\
             EROFS_ORACLE phase=complete status=accepted",
            "",
            0,
            false,
        ));
        assert_eq!(result.status, OracleStatus::ResourceExhausted);
    }

    #[test]
    fn log_capture_bounds_retained_bytes_while_draining() {
        let captured = capture_log(std::io::Cursor::new(vec![b'x'; 32 * 1024]), 7);
        assert_eq!(captured.bytes, b"xxxxxxx");
        assert!(captured.truncated);
    }

    #[test]
    fn timeout_wins_over_missing_marker() {
        assert_eq!(
            classify_qemu(&output("", "", 1, true)).status,
            OracleStatus::TimedOut
        );
    }

    #[test]
    fn fsck_unknown_failure_is_harness_error() {
        assert_eq!(
            classify_fsck(&output("", "mystery", 2, false)).status,
            OracleStatus::HarnessError
        );
    }

    #[test]
    fn rust_requires_final_marker() {
        assert_eq!(
            classify_rust(&output(
                "{\"phase\":\"traverse\",\"status\":\"accepted\"}",
                "",
                0,
                false,
            ))
            .status,
            OracleStatus::HarnessError
        );
    }
    #[test]
    fn sandbox_timeout_kills_child_when_user_namespaces_are_available() {
        let limits = ResourceLimits {
            timeout_ms: 20,
            cpu_seconds: 1,
            address_space_bytes: 64 << 20,
            file_bytes: 1 << 20,
            processes: 4,
            output_bytes: 1024,
        };
        let directory = std::env::temp_dir();
        let output = run_sandboxed(
            &["/usr/bin/sleep".into(), "2".into()],
            &directory,
            &limits,
            false,
        )
        .unwrap();
        if output.timed_out {
            return;
        }
        assert!(
            output.status.is_some_and(|status| !status.success())
                && String::from_utf8_lossy(&output.stderr).contains("unshare"),
            "sandbox unexpectedly completed without timing out: {output:?}"
        );
    }

    #[test]
    fn missing_oracle_is_harness_output() {
        let output = run_sandboxed(
            &["/definitely/missing/oracle".into()],
            &std::env::temp_dir(),
            &ResourceLimits::default(),
            false,
        )
        .unwrap();
        assert!(output.status.is_none());
        assert!(String::from_utf8_lossy(&output.stderr).contains("missing"));
    }
}
