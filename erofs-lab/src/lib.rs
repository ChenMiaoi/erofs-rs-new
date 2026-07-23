//! Deterministic EROFS mutation planning, materialization, and byte replay.

#![forbid(unsafe_code)]
pub mod campaign;
pub mod oracle;

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use erofs_format::{
    SliceReader,
    locator::{Locator, MetadataSpace, ObjectRef as FormatObjectRef, ParseMode},
    schema::{Encoding, SCHEMA_IDENTITY, field_by_id},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const SAMPLE_SCHEMA: &str = "erofs-mutation-sample/v1";
const RESOLUTION_SEMANTICS: &str = "immutable-baseline/v1";
const SB_CHECKSUM_FEATURE: u32 = 1;
const SUPER_OFFSET: usize = 1024;
const CHECKSUM_OFFSET: usize = SUPER_OFFSET + 4;
const O_NOFOLLOW: i32 = 0o400000;

/// Mutation interpretation mode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationMode {
    Corrupt,
    Consistent,
    Raw,
}

/// Superblock checksum policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityPolicy {
    Preserve,
    Recalculate,
    Invalidate,
}

/// Canonical M2 object selector.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectRef {
    Superblock,
    Inode {
        space: String,
        nid: String,
    },
    Dirent {
        directory: String,
        block: String,
        index: u32,
    },
}

impl ObjectRef {
    fn to_format(&self) -> Result<FormatObjectRef, Error> {
        match self {
            Self::Superblock => Ok(FormatObjectRef::Superblock),
            Self::Inode { space, nid } if space == "primary" => Ok(FormatObjectRef::Inode {
                space: MetadataSpace::Primary,
                nid: parse_u64(nid)?,
            }),
            Self::Dirent {
                directory,
                block,
                index,
            } => Ok(FormatObjectRef::Dirent {
                directory: parse_u64(directory)?,
                block: parse_u64(block)?,
                index: *index,
            }),
            Self::Inode { .. } => Err(Error::Unsupported("only primary inode space is supported")),
        }
    }
}

/// User mutation request. All symbolic requests resolve against one immutable baseline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationIntent {
    SetValue {
        object: ObjectRef,
        field: String,
        value: u64,
    },
    UpdateBits {
        object: ObjectRef,
        field: String,
        set: u64,
        clear: u64,
    },
    ReplaceFixedBytes {
        object: ObjectRef,
        field: String,
        bytes: Vec<u8>,
    },
    PatchBytes {
        offset: u64,
        bytes: Vec<u8>,
    },
    TruncateImage {
        new_len: u64,
    },
}

/// Exact resolved byte patch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedPatch {
    pub origin: String,
    pub object: Option<ObjectRef>,
    pub field: Option<String>,
    pub span: ManifestSpan,
    pub encoding: String,
    pub operator: String,
    pub before_hex: String,
    pub after_hex: String,
}

/// JSON-safe span with decimal string integers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSpan {
    pub offset: String,
    pub length: String,
}

/// Explicit image resize operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Resize {
    Truncate {
        before_length: String,
        after_length: String,
    },
}

/// Integrity action recorded independently from exact repair bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrityRecord {
    pub domain: String,
    pub policy: IntegrityPolicy,
    pub status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub sha256: String,
    pub length: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AbiIdentity {
    pub linux_commit: String,
    pub schema_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resolution {
    pub semantics: String,
    pub mode: MutationMode,
}

/// Immutable sample manifest. Exact patches, not symbolic recipes, are replay authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SampleManifest {
    pub schema: String,
    pub abi: AbiIdentity,
    pub parent: Identity,
    pub resolution: Resolution,
    pub plan_sha256: String,
    pub patches: Vec<ResolvedPatch>,
    pub resize: Option<Resize>,
    pub integrity: Vec<IntegrityRecord>,
    pub output: Identity,
}

/// Frozen plan before output identity is known.
#[derive(Clone, Debug)]
pub struct ResolvedPlan {
    pub parent_sha256: String,
    pub parent_length: u64,
    pub mode: MutationMode,
    pub patches: Vec<ResolvedPatch>,
    pub resize: Option<Resize>,
    pub integrity: Vec<IntegrityRecord>,
    pub plan_sha256: String,
}

/// Published content-addressed sample.
#[derive(Clone, Debug)]
pub struct PublishedSample {
    pub directory: PathBuf,
    pub image: PathBuf,
    pub manifest: PathBuf,
    pub output_sha256: String,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid decimal integer: {0}")]
    InvalidInteger(String),
    #[error("invalid hex bytes")]
    InvalidHex,
    #[error("unsupported capability: {0}")]
    Unsupported(&'static str),
    #[error("field resolution failed: {0}")]
    Resolve(String),
    #[error("value does not fit field encoding")]
    ValueOverflow,
    #[error("patch span overflow or out of bounds")]
    Bounds,
    #[error("conflicting patches at image offset {0}")]
    Conflict(u64),
    #[error("truncate conflicts with a patch or integrity range")]
    TruncateConflict,
    #[error("preimage mismatch at image offset {0}")]
    Preimage(u64),
    #[error("parent identity mismatch")]
    ParentIdentity,
    #[error("output identity mismatch")]
    OutputIdentity,
    #[error("input must be a regular non-symlink file")]
    InvalidInput,
    #[error("corpus entry already exists but is inconsistent")]
    CorpusCorruption,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WriteMeta {
    origin: String,
    object: Option<ObjectRef>,
    field: Option<String>,
    encoding: String,
    operator: String,
}

#[derive(Clone, Debug)]
struct PlannedByte {
    before: u8,
    after: u8,
    meta: WriteMeta,
}

type WriteMap = BTreeMap<u64, PlannedByte>;

struct WriteRequest<'a> {
    offset: u64,
    after: &'a [u8],
    meta: WriteMeta,
}

struct PatchBuilder {
    offset: u64,
    before: Vec<u8>,
    after: Vec<u8>,
    meta: WriteMeta,
}

/// Resolves all intents against `parent`, then applies explicit integrity repair.
pub fn plan(
    parent: &[u8],
    intents: &[MutationIntent],
    mode: MutationMode,
    integrity: IntegrityPolicy,
) -> Result<ResolvedPlan, Error> {
    if mode == MutationMode::Raw
        && intents.iter().any(|intent| {
            !matches!(
                intent,
                MutationIntent::PatchBytes { .. } | MutationIntent::TruncateImage { .. }
            )
        })
    {
        return Err(Error::Unsupported(
            "raw mode accepts only raw patches and truncate",
        ));
    }
    let reader = SliceReader::new(parent);
    let parse_mode = if mode == MutationMode::Consistent {
        ParseMode::Strict
    } else {
        ParseMode::Tolerant
    };
    let locator = Locator::with_mode(&reader, parse_mode)
        .map_err(|error| Error::Resolve(format!("{error:?}")))?;
    let mut writes = WriteMap::new();
    let mut truncate = None;

    for intent in intents {
        match intent {
            MutationIntent::TruncateImage { new_len } => {
                if truncate.replace(*new_len).is_some() {
                    return Err(Error::Conflict(*new_len));
                }
            }
            MutationIntent::PatchBytes { offset, bytes } => add_write(
                parent,
                &mut writes,
                WriteRequest {
                    offset: *offset,
                    after: bytes,
                    meta: WriteMeta {
                        origin: "user".into(),
                        object: None,
                        field: None,
                        encoding: "bytes".into(),
                        operator: "raw".into(),
                    },
                },
            )?,
            MutationIntent::SetValue {
                object,
                field,
                value,
            } => {
                let definition = field_by_id(field)
                    .ok_or_else(|| Error::Resolve(format!("unknown field {field}")))?;
                let occurrence = locator
                    .locate(object.to_format()?, definition)
                    .map_err(|error| Error::Resolve(format!("{error:?}")))?;
                let bytes = encode(definition.encoding, definition.storage.len, *value)?;
                add_write(
                    parent,
                    &mut writes,
                    WriteRequest {
                        offset: occurrence.span.offset,
                        after: &bytes,
                        meta: WriteMeta {
                            origin: "user".into(),
                            object: Some(object.clone()),
                            field: Some(field.clone()),
                            encoding: encoding_name(definition.encoding).into(),
                            operator: "set".into(),
                        },
                    },
                )?;
            }
            MutationIntent::ReplaceFixedBytes {
                object,
                field,
                bytes,
            } => {
                let definition = field_by_id(field)
                    .ok_or_else(|| Error::Resolve(format!("unknown field {field}")))?;
                if bytes.len() as u64 != definition.storage.len {
                    return Err(Error::Bounds);
                }
                let occurrence = locator
                    .locate(object.to_format()?, definition)
                    .map_err(|error| Error::Resolve(format!("{error:?}")))?;
                add_write(
                    parent,
                    &mut writes,
                    WriteRequest {
                        offset: occurrence.span.offset,
                        after: bytes,
                        meta: WriteMeta {
                            origin: "user".into(),
                            object: Some(object.clone()),
                            field: Some(field.clone()),
                            encoding: encoding_name(definition.encoding).into(),
                            operator: "replace".into(),
                        },
                    },
                )?;
            }
            MutationIntent::UpdateBits {
                object,
                field,
                set,
                clear,
            } => {
                if set & clear != 0 {
                    return Err(Error::Conflict(0));
                }
                let definition = field_by_id(field)
                    .ok_or_else(|| Error::Resolve(format!("unknown field {field}")))?;
                if definition.encoding == Encoding::Bytes {
                    return Err(Error::Unsupported("bit update requires an integer field"));
                }
                let occurrence = locator
                    .locate(object.to_format()?, definition)
                    .map_err(|error| Error::Resolve(format!("{error:?}")))?;
                let width_mask = if definition.storage.len == 8 {
                    u64::MAX
                } else {
                    (1_u64 << (definition.storage.len * 8)) - 1
                };
                if (set | clear) & !width_mask != 0 {
                    return Err(Error::ValueOverflow);
                }
                let start = usize::try_from(occurrence.span.offset).map_err(|_| Error::Bounds)?;
                let len = usize::try_from(definition.storage.len).map_err(|_| Error::Bounds)?;
                let mut current = decode_unsigned(definition.encoding, &parent[start..start + len]);
                for byte in 0..len {
                    if let Some(write) = writes.get(&(occurrence.span.offset + byte as u64)) {
                        current &= !(0xff << (byte * 8));
                        current |= u64::from(write.after) << (byte * 8);
                    }
                }
                let bytes = encode(
                    definition.encoding,
                    definition.storage.len,
                    (current | set) & !clear,
                )?;
                add_write(
                    parent,
                    &mut writes,
                    WriteRequest {
                        offset: occurrence.span.offset,
                        after: &bytes,
                        meta: WriteMeta {
                            origin: "user".into(),
                            object: Some(object.clone()),
                            field: Some(field.clone()),
                            encoding: encoding_name(definition.encoding).into(),
                            operator: "bits".into(),
                        },
                    },
                )?;
            }
        }
    }

    let final_len = truncate.unwrap_or(parent.len() as u64);
    if final_len > parent.len() as u64 {
        return Err(Error::Bounds);
    }
    if writes.keys().any(|offset| *offset >= final_len) {
        return Err(Error::TruncateConflict);
    }

    let mut integrity_records = Vec::new();
    apply_integrity(
        parent,
        final_len,
        integrity,
        &mut writes,
        &mut integrity_records,
    )?;
    let patches = collapse_writes(&writes);
    let resize = truncate.map(|after| Resize::Truncate {
        before_length: parent.len().to_string(),
        after_length: after.to_string(),
    });
    let parent_sha256 = sha256(parent);
    let plan_sha256 = plan_digest(
        &parent_sha256,
        parent.len() as u64,
        mode,
        &patches,
        &resize,
        &integrity_records,
    )?;
    Ok(ResolvedPlan {
        parent_sha256,
        parent_length: parent.len() as u64,
        mode,
        patches,
        resize,
        integrity: integrity_records,
        plan_sha256,
    })
}

fn apply_integrity(
    parent: &[u8],
    final_len: u64,
    policy: IntegrityPolicy,
    writes: &mut WriteMap,
    records: &mut Vec<IntegrityRecord>,
) -> Result<(), Error> {
    let feature = logical_u32(parent, writes, SUPER_OFFSET as u64 + 8)?;
    if feature & SB_CHECKSUM_FEATURE == 0 {
        records.push(IntegrityRecord {
            domain: "erofs.superblock.crc32c".into(),
            policy,
            status: "not_applicable:feature_disabled".into(),
        });
        return Ok(());
    }
    if policy == IntegrityPolicy::Preserve {
        records.push(IntegrityRecord {
            domain: "erofs.superblock.crc32c".into(),
            policy,
            status: "preserved".into(),
        });
        return Ok(());
    }
    let blkszbits = logical_byte(parent, writes, (SUPER_OFFSET + 12) as u64)?;
    let block_size = 1_u64
        .checked_shl(u32::from(blkszbits))
        .ok_or(Error::Bounds)?;
    let coverage_len = if block_size > SUPER_OFFSET as u64 {
        block_size - SUPER_OFFSET as u64
    } else {
        block_size
    };
    let coverage_end = SUPER_OFFSET as u64 + coverage_len;
    if coverage_end > final_len {
        return Err(Error::TruncateConflict);
    }
    let mut block =
        parent[SUPER_OFFSET..usize::try_from(coverage_end).map_err(|_| Error::Bounds)?].to_vec();
    for (&offset, write) in writes.iter() {
        if offset >= SUPER_OFFSET as u64 && offset < coverage_end {
            block[usize::try_from(offset - SUPER_OFFSET as u64).map_err(|_| Error::Bounds)?] =
                write.after;
        }
    }
    block[4..8].fill(0);
    let mut checksum = crc32c(!0, &block);
    if policy == IntegrityPolicy::Invalidate {
        checksum ^= 1;
    }
    add_write(
        parent,
        writes,
        WriteRequest {
            offset: CHECKSUM_OFFSET as u64,
            after: &checksum.to_le_bytes(),
            meta: WriteMeta {
                origin: "repair:erofs.superblock.crc32c".into(),
                object: Some(ObjectRef::Superblock),
                field: Some("erofs.superblock.checksum".into()),
                encoding: "le-u32".into(),
                operator: if policy == IntegrityPolicy::Invalidate {
                    "invalidate".into()
                } else {
                    "recalculate".into()
                },
            },
        },
    )?;
    records.push(IntegrityRecord {
        domain: "erofs.superblock.crc32c".into(),
        policy,
        status: "applied".into(),
    });
    Ok(())
}
/// Applies a frozen plan in memory after validating every preimage.
///
/// Campaigns use this to deduplicate byte identities before publishing a
/// second semantic plan for identical output bytes.
pub fn apply_resolved_plan(parent: &[u8], plan: &ResolvedPlan) -> Result<Vec<u8>, Error> {
    if parent.len() as u64 != plan.parent_length || sha256(parent) != plan.parent_sha256 {
        return Err(Error::ParentIdentity);
    }
    apply_plan_bytes(parent, &plan.patches, plan.resize.as_ref())
}

/// Materializes and atomically publishes a plan under `samples/sha256/<hash>`.
pub fn materialize(
    parent_path: &Path,
    corpus: &Path,
    plan: &ResolvedPlan,
) -> Result<PublishedSample, Error> {
    let mut parent = open_input(parent_path)?;
    let metadata = parent.metadata()?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| Error::Bounds)?);
    parent.read_to_end(&mut bytes)?;
    if metadata.len() != plan.parent_length || sha256(&bytes) != plan.parent_sha256 {
        return Err(Error::ParentIdentity);
    }
    let output = apply_plan_bytes(&bytes, &plan.patches, plan.resize.as_ref())?;
    let output_hash = sha256(&output);
    let manifest = manifest_from_plan(plan, &output_hash, output.len() as u64);
    publish(corpus, &output, &manifest)
}

/// Replays a manifest without consulting the current schema or locator.
pub fn replay(
    parent_path: &Path,
    corpus: &Path,
    manifest_path: &Path,
) -> Result<PublishedSample, Error> {
    let manifest: SampleManifest = serde_json::from_slice(&fs::read(manifest_path)?)?;
    validate_manifest(&manifest)?;
    let mut parent = open_input(parent_path)?;
    let mut bytes = Vec::new();
    parent.read_to_end(&mut bytes)?;
    if sha256(&bytes) != manifest.parent.sha256 || bytes.len().to_string() != manifest.parent.length
    {
        return Err(Error::ParentIdentity);
    }
    let output = apply_plan_bytes(&bytes, &manifest.patches, manifest.resize.as_ref())?;
    if sha256(&output) != manifest.output.sha256
        || output.len().to_string() != manifest.output.length
    {
        return Err(Error::OutputIdentity);
    }
    publish(corpus, &output, &manifest)
}

fn publish(
    corpus: &Path,
    output: &[u8],
    manifest: &SampleManifest,
) -> Result<PublishedSample, Error> {
    let samples = corpus.join("samples/sha256");
    fs::create_dir_all(&samples)?;
    let final_dir = samples.join(&manifest.output.sha256);
    if final_dir.exists() {
        return verify_existing(final_dir, manifest);
    }
    let stage = samples.join(format!(
        ".stage-{}-{}",
        std::process::id(),
        manifest.output.sha256
    ));
    match fs::remove_dir_all(&stage) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::create_dir(&stage)?;
    let image_path = stage.join("image.erofs");
    let manifest_path = stage.join("sample.json");
    let mut image = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&image_path)?;
    image.write_all(output)?;
    image.sync_all()?;
    let manifest_bytes = canonical_manifest(manifest)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest_path)?;
    file.write_all(&manifest_bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::set_permissions(&image_path, fs::Permissions::from_mode(0o444))?;
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o444))?;
    File::open(&stage)?.sync_all()?;
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o555))?;
    match rustix::fs::renameat_with(
        rustix::fs::CWD,
        &stage,
        rustix::fs::CWD,
        &final_dir,
        rustix::fs::RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::EXIST => {
            fs::remove_dir_all(&stage)?;
            return verify_existing(final_dir, manifest);
        }
        Err(error) => {
            let _ = fs::remove_dir_all(&stage);
            return Err(std::io::Error::from_raw_os_error(error.raw_os_error()).into());
        }
    }
    File::open(&samples)?.sync_all()?;
    Ok(PublishedSample {
        image: final_dir.join("image.erofs"),
        manifest: final_dir.join("sample.json"),
        directory: final_dir,
        output_sha256: manifest.output.sha256.clone(),
    })
}

fn verify_existing(
    directory: PathBuf,
    manifest: &SampleManifest,
) -> Result<PublishedSample, Error> {
    let image = directory.join("image.erofs");
    let manifest_path = directory.join("sample.json");
    if sha256(&fs::read(&image)?) != manifest.output.sha256 {
        return Err(Error::CorpusCorruption);
    }
    let existing: SampleManifest = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    if canonical_manifest(&existing)? != canonical_manifest(manifest)? {
        return Err(Error::CorpusCorruption);
    }
    Ok(PublishedSample {
        image,
        manifest: manifest_path,
        directory,
        output_sha256: manifest.output.sha256.clone(),
    })
}

fn open_input(path: &Path) -> Result<File, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(40) {
                Error::InvalidInput
            } else {
                Error::Io(error)
            }
        })?;
    if !file.metadata()?.file_type().is_file() {
        return Err(Error::InvalidInput);
    }
    Ok(file)
}

fn apply_plan_bytes(
    parent: &[u8],
    patches: &[ResolvedPatch],
    resize: Option<&Resize>,
) -> Result<Vec<u8>, Error> {
    let mut output = parent.to_vec();
    for patch in patches {
        let offset = usize::try_from(parse_u64(&patch.span.offset)?).map_err(|_| Error::Bounds)?;
        let len = usize::try_from(parse_u64(&patch.span.length)?).map_err(|_| Error::Bounds)?;
        let end = offset.checked_add(len).ok_or(Error::Bounds)?;
        let before = decode_hex(&patch.before_hex)?;
        let after = decode_hex(&patch.after_hex)?;
        if before.len() != len
            || after.len() != len
            || output.get(offset..end) != Some(before.as_slice())
        {
            return Err(Error::Preimage(offset as u64));
        }
        output[offset..end].copy_from_slice(&after);
    }
    if let Some(Resize::Truncate {
        before_length,
        after_length,
    }) = resize
    {
        if parse_u64(before_length)? != parent.len() as u64 {
            return Err(Error::ParentIdentity);
        }
        output.truncate(usize::try_from(parse_u64(after_length)?).map_err(|_| Error::Bounds)?);
    }
    Ok(output)
}

fn manifest_from_plan(plan: &ResolvedPlan, output_hash: &str, output_len: u64) -> SampleManifest {
    SampleManifest {
        schema: SAMPLE_SCHEMA.into(),
        abi: AbiIdentity {
            linux_commit: SCHEMA_IDENTITY.linux_commit.into(),
            schema_digest: SCHEMA_IDENTITY.digest.into(),
        },
        parent: Identity {
            sha256: plan.parent_sha256.clone(),
            length: plan.parent_length.to_string(),
        },
        resolution: Resolution {
            semantics: RESOLUTION_SEMANTICS.into(),
            mode: plan.mode,
        },
        plan_sha256: plan.plan_sha256.clone(),
        patches: plan.patches.clone(),
        resize: plan.resize.clone(),
        integrity: plan.integrity.clone(),
        output: Identity {
            sha256: output_hash.into(),
            length: output_len.to_string(),
        },
    }
}

fn validate_manifest(manifest: &SampleManifest) -> Result<(), Error> {
    if manifest.schema != SAMPLE_SCHEMA || manifest.resolution.semantics != RESOLUTION_SEMANTICS {
        return Err(Error::Unsupported("manifest schema"));
    }
    let digest = plan_digest(
        &manifest.parent.sha256,
        parse_u64(&manifest.parent.length)?,
        manifest.resolution.mode,
        &manifest.patches,
        &manifest.resize,
        &manifest.integrity,
    )?;
    if digest != manifest.plan_sha256 {
        return Err(Error::OutputIdentity);
    }
    Ok(())
}

fn plan_digest(
    parent_hash: &str,
    parent_len: u64,
    mode: MutationMode,
    patches: &[ResolvedPatch],
    resize: &Option<Resize>,
    integrity: &[IntegrityRecord],
) -> Result<String, Error> {
    #[derive(Serialize)]
    struct DigestDocument<'a> {
        parent_sha256: &'a str,
        parent_length: String,
        mode: MutationMode,
        patches: &'a [ResolvedPatch],
        resize: &'a Option<Resize>,
        integrity: &'a [IntegrityRecord],
    }
    Ok(sha256(&serde_json::to_vec(&DigestDocument {
        parent_sha256: parent_hash,
        parent_length: parent_len.to_string(),
        mode,
        patches,
        resize,
        integrity,
    })?))
}

fn add_write(parent: &[u8], writes: &mut WriteMap, request: WriteRequest<'_>) -> Result<(), Error> {
    let start = usize::try_from(request.offset).map_err(|_| Error::Bounds)?;
    let end = start
        .checked_add(request.after.len())
        .ok_or(Error::Bounds)?;
    let before = parent.get(start..end).ok_or(Error::Bounds)?;
    for (index, (&before, &after)) in before.iter().zip(request.after).enumerate() {
        let absolute = request.offset + index as u64;
        if let Some(existing) = writes.get_mut(&absolute) {
            if existing.meta.operator != "bits" || request.meta.operator != "bits" {
                return Err(Error::Conflict(absolute));
            }
            existing.after = after;
        } else if before == after {
            continue;
        } else {
            writes.insert(
                absolute,
                PlannedByte {
                    before,
                    after,
                    meta: request.meta.clone(),
                },
            );
        }
    }
    Ok(())
}
fn collapse_writes(writes: &WriteMap) -> Vec<ResolvedPatch> {
    let mut result = Vec::new();
    let mut current: Option<PatchBuilder> = None;
    for (&offset, write) in writes {
        let same = current.as_ref().is_some_and(|patch| {
            patch.offset + patch.before.len() as u64 == offset && patch.meta == write.meta
        });
        if !same {
            if let Some(patch) = current.take() {
                result.push(make_patch(patch));
            }
            current = Some(PatchBuilder {
                offset,
                before: Vec::new(),
                after: Vec::new(),
                meta: write.meta.clone(),
            });
        }
        let patch = current.as_mut().unwrap();
        patch.before.push(write.before);
        patch.after.push(write.after);
    }
    if let Some(patch) = current {
        result.push(make_patch(patch));
    }
    result
}

fn make_patch(patch: PatchBuilder) -> ResolvedPatch {
    ResolvedPatch {
        origin: patch.meta.origin,
        object: patch.meta.object,
        field: patch.meta.field,
        span: ManifestSpan {
            offset: patch.offset.to_string(),
            length: patch.before.len().to_string(),
        },
        encoding: patch.meta.encoding,
        operator: patch.meta.operator,
        before_hex: encode_hex(&patch.before),
        after_hex: encode_hex(&patch.after),
    }
}

fn logical_byte(parent: &[u8], writes: &WriteMap, offset: u64) -> Result<u8, Error> {
    writes
        .get(&offset)
        .map(|write| write.after)
        .or_else(|| parent.get(offset as usize).copied())
        .ok_or(Error::Bounds)
}
fn logical_u32(parent: &[u8], writes: &WriteMap, offset: u64) -> Result<u32, Error> {
    let mut bytes = [0; 4];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = logical_byte(parent, writes, offset + index as u64)?;
    }
    Ok(u32::from_le_bytes(bytes))
}
fn encode(encoding: Encoding, len: u64, value: u64) -> Result<Vec<u8>, Error> {
    let bytes = match encoding {
        Encoding::U8 => vec![u8::try_from(value).map_err(|_| Error::ValueOverflow)?],
        Encoding::LeU16 => u16::try_from(value)
            .map_err(|_| Error::ValueOverflow)?
            .to_le_bytes()
            .to_vec(),
        Encoding::LeU32 => u32::try_from(value)
            .map_err(|_| Error::ValueOverflow)?
            .to_le_bytes()
            .to_vec(),
        Encoding::LeU64 => value.to_le_bytes().to_vec(),
        Encoding::Bytes => return Err(Error::Unsupported("set requires an integer field")),
    };
    if bytes.len() as u64 != len {
        return Err(Error::ValueOverflow);
    }
    Ok(bytes)
}
fn decode_unsigned(encoding: Encoding, bytes: &[u8]) -> u64 {
    match encoding {
        Encoding::U8 => u64::from(bytes[0]),
        Encoding::LeU16 => u64::from(u16::from_le_bytes(bytes.try_into().unwrap())),
        Encoding::LeU32 => u64::from(u32::from_le_bytes(bytes.try_into().unwrap())),
        Encoding::LeU64 => u64::from_le_bytes(bytes.try_into().unwrap()),
        Encoding::Bytes => 0,
    }
}
fn encoding_name(value: Encoding) -> &'static str {
    match value {
        Encoding::U8 => "u8",
        Encoding::LeU16 => "le-u16",
        Encoding::LeU32 => "le-u32",
        Encoding::LeU64 => "le-u64",
        Encoding::Bytes => "bytes",
    }
}
fn crc32c(mut crc: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0x82f6_3b78 } else { 0 };
        }
    }
    crc
}
fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn parse_u64(value: &str) -> Result<u64, Error> {
    value
        .parse()
        .map_err(|_| Error::InvalidInteger(value.into()))
}
fn encode_hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 15) as usize] as char);
    }
    out
}
fn decode_hex(value: &str) -> Result<Vec<u8>, Error> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::InvalidHex);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let h = (pair[0] as char).to_digit(16).ok_or(Error::InvalidHex)?;
            let l = (pair[1] as char).to_digit(16).ok_or(Error::InvalidHex)?;
            Ok(((h << 4) | l) as u8)
        })
        .collect()
}
fn canonical_manifest(manifest: &SampleManifest) -> Result<Vec<u8>, Error> {
    Ok(serde_json::to_vec(manifest)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn image() -> Vec<u8> {
        let mut image = vec![0; 4096];
        image[1024..1028].copy_from_slice(&erofs_format::SUPERBLOCK_MAGIC.to_le_bytes());
        image[1036] = 12;
        image[1037] = 0;
        image
    }
    #[test]
    fn raw_plan_replays_exact_bytes() {
        let parent = image();
        let plan = plan(
            &parent,
            &[MutationIntent::PatchBytes {
                offset: 20,
                bytes: vec![1, 2],
            }],
            MutationMode::Raw,
            IntegrityPolicy::Preserve,
        )
        .unwrap();
        let output = apply_plan_bytes(&parent, &plan.patches, plan.resize.as_ref()).unwrap();
        assert_eq!(&output[20..22], &[1, 2]);
    }
    #[test]
    fn overlapping_raw_patches_are_rejected() {
        let parent = image();
        assert!(matches!(
            plan(
                &parent,
                &[
                    MutationIntent::PatchBytes {
                        offset: 20,
                        bytes: vec![1]
                    },
                    MutationIntent::PatchBytes {
                        offset: 20,
                        bytes: vec![2]
                    },
                ],
                MutationMode::Raw,
                IntegrityPolicy::Preserve,
            ),
            Err(Error::Conflict(20))
        ));
    }

    #[test]
    fn field_set_and_bit_updates_use_baseline_location() {
        let parent = image();
        let plan = plan(
            &parent,
            &[
                MutationIntent::SetValue {
                    object: ObjectRef::Superblock,
                    field: "erofs.superblock.fixed_nsec".into(),
                    value: 7,
                },
                MutationIntent::UpdateBits {
                    object: ObjectRef::Superblock,
                    field: "erofs.superblock.feature_compat".into(),
                    set: 2,
                    clear: 0,
                },
            ],
            MutationMode::Corrupt,
            IntegrityPolicy::Preserve,
        )
        .unwrap();
        let output = apply_plan_bytes(&parent, &plan.patches, None).unwrap();
        assert_eq!(&output[1056..1060], &7_u32.to_le_bytes());
        assert_eq!(&output[1032..1036], &2_u32.to_le_bytes());
    }

    #[test]
    fn replay_rejects_changed_preimage() {
        let parent = image();
        let plan = plan(
            &parent,
            &[MutationIntent::PatchBytes {
                offset: 20,
                bytes: vec![1],
            }],
            MutationMode::Raw,
            IntegrityPolicy::Preserve,
        )
        .unwrap();
        let mut changed = parent;
        changed[20] = 9;
        assert!(matches!(
            apply_plan_bytes(&changed, &plan.patches, None),
            Err(Error::Preimage(20))
        ));
    }

    #[test]
    fn crc_repair_is_explicit_and_verifiable() {
        let mut parent = image();
        parent[1032..1036].copy_from_slice(&SB_CHECKSUM_FEATURE.to_le_bytes());
        let plan = plan(
            &parent,
            &[MutationIntent::PatchBytes {
                offset: 1100,
                bytes: vec![7],
            }],
            MutationMode::Corrupt,
            IntegrityPolicy::Recalculate,
        )
        .unwrap();
        assert!(plan.patches.iter().any(|patch| {
            patch.origin == "repair:erofs.superblock.crc32c"
                && patch.span.offset == CHECKSUM_OFFSET.to_string()
        }));
        let output = apply_plan_bytes(&parent, &plan.patches, None).unwrap();
        let mut checked = output[SUPER_OFFSET..].to_vec();
        checked[4..8].fill(0);
        let expected = crc32c(!0, &checked);
        assert_eq!(
            u32::from_le_bytes(
                output[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4]
                    .try_into()
                    .unwrap()
            ),
            expected
        );
    }

    #[test]
    fn invalidate_differs_by_one_fixed_bit() {
        let mut parent = image();
        parent[1032..1036].copy_from_slice(&SB_CHECKSUM_FEATURE.to_le_bytes());
        let valid = plan(
            &parent,
            &[],
            MutationMode::Corrupt,
            IntegrityPolicy::Recalculate,
        )
        .unwrap();
        let invalid = plan(
            &parent,
            &[],
            MutationMode::Corrupt,
            IntegrityPolicy::Invalidate,
        )
        .unwrap();
        let valid_bytes = apply_plan_bytes(&parent, &valid.patches, None).unwrap();
        let invalid_bytes = apply_plan_bytes(&parent, &invalid.patches, None).unwrap();
        let valid_crc = u32::from_le_bytes(valid_bytes[1028..1032].try_into().unwrap());
        let invalid_crc = u32::from_le_bytes(invalid_bytes[1028..1032].try_into().unwrap());
        assert_eq!(valid_crc ^ invalid_crc, 1);
    }

    #[test]
    fn truncate_cannot_remove_patch() {
        let parent = image();
        assert!(matches!(
            plan(
                &parent,
                &[
                    MutationIntent::PatchBytes {
                        offset: 3000,
                        bytes: vec![1]
                    },
                    MutationIntent::TruncateImage { new_len: 2000 },
                ],
                MutationMode::Raw,
                IntegrityPolicy::Preserve,
            ),
            Err(Error::TruncateConflict)
        ));
    }

    #[test]
    fn materialize_and_replay_preserve_parent_and_output_identity() {
        let root = std::env::temp_dir().join(format!("erofs-lab-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let parent_path = root.join("parent.erofs");
        let parent = image();
        fs::write(&parent_path, &parent).unwrap();
        let plan = plan(
            &parent,
            &[MutationIntent::PatchBytes {
                offset: 20,
                bytes: vec![1, 2],
            }],
            MutationMode::Raw,
            IntegrityPolicy::Preserve,
        )
        .unwrap();
        let first = materialize(&parent_path, &root.join("corpus-a"), &plan).unwrap();
        let second = replay(&parent_path, &root.join("corpus-b"), &first.manifest).unwrap();
        assert_eq!(fs::read(&parent_path).unwrap(), parent);
        assert_eq!(
            fs::read(first.image).unwrap(),
            fs::read(second.image).unwrap()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn materializer_rejects_symlink_parent() {
        use std::os::unix::fs::symlink;

        let root =
            std::env::temp_dir().join(format!("erofs-lab-symlink-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let parent_path = root.join("parent.erofs");
        let link_path = root.join("link.erofs");
        let parent = image();
        fs::write(&parent_path, &parent).unwrap();
        symlink(&parent_path, &link_path).unwrap();
        let plan = plan(&parent, &[], MutationMode::Raw, IntegrityPolicy::Preserve).unwrap();
        assert!(matches!(
            materialize(&link_path, &root.join("corpus"), &plan),
            Err(Error::InvalidInput)
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn checksum_user_write_conflicts_with_repair() {
        let mut parent = image();
        parent[1032..1036].copy_from_slice(&SB_CHECKSUM_FEATURE.to_le_bytes());
        assert!(matches!(
            plan(
                &parent,
                &[MutationIntent::PatchBytes {
                    offset: 1028,
                    bytes: vec![1, 2, 3, 4],
                }],
                MutationMode::Corrupt,
                IntegrityPolicy::Recalculate,
            ),
            Err(Error::Conflict(offset)) if (1028..=1031).contains(&offset)
        ));
    }

    #[test]
    fn raw_mode_rejects_symbolic_intents() {
        let parent = image();
        assert!(matches!(
            plan(
                &parent,
                &[MutationIntent::SetValue {
                    object: ObjectRef::Superblock,
                    field: "erofs.superblock.fixed_nsec".into(),
                    value: 1,
                }],
                MutationMode::Raw,
                IntegrityPolicy::Preserve,
            ),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn truncate_records_resize_without_fake_patch() {
        let parent = image();
        let plan = plan(
            &parent,
            &[MutationIntent::TruncateImage { new_len: 2048 }],
            MutationMode::Raw,
            IntegrityPolicy::Preserve,
        )
        .unwrap();
        assert!(plan.patches.is_empty());
        assert_eq!(
            plan.resize,
            Some(Resize::Truncate {
                before_length: "4096".into(),
                after_length: "2048".into(),
            })
        );
    }

    #[test]
    fn repeated_identical_non_bit_patch_is_still_rejected() {
        let parent = image();
        assert!(matches!(
            plan(
                &parent,
                &[
                    MutationIntent::PatchBytes {
                        offset: 20,
                        bytes: vec![1]
                    },
                    MutationIntent::PatchBytes {
                        offset: 20,
                        bytes: vec![1]
                    },
                ],
                MutationMode::Raw,
                IntegrityPolicy::Preserve,
            ),
            Err(Error::Conflict(20))
        ));
    }

    #[test]
    fn checksum_matches_erofs_seed_and_polynomial() {
        assert_eq!(crc32c(!0, b"123456789"), 0x1cf9_6d7c);
    }
}
