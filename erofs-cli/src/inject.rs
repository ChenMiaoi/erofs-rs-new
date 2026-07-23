use std::{fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand, ValueEnum};
use erofs_lab::{
    IntegrityPolicy, MutationIntent, MutationMode, ObjectRef, PublishedSample, materialize, plan,
};

#[derive(Args, Debug)]
pub struct InjectArgs {
    #[command(subcommand)]
    command: InjectCommand,
}

#[derive(Subcommand, Debug)]
enum InjectCommand {
    Set(FieldMutation),
    Bits(BitMutation),
    Bytes(ByteMutation),
    Raw(RawMutation),
    Truncate(TruncateMutation),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ObjectKind {
    Superblock,
    Inode,
    Dirent,
    SuperblockExtension,
    DeviceSlot,
    Chunk,
    XattrHeader,
    SharedXattrId,
    InlineXattr,
    XattrLongPrefix,
    CompressionConfig,
    CompressionMap,
    CompressionIndex,
    CompressionCompactPack,
    CompressionExtent,
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Corrupt,
    Consistent,
    Raw,
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Integrity {
    Preserve,
    Recalculate,
    Invalidate,
}

#[derive(Args, Debug)]
struct Common {
    image: PathBuf,
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long, value_enum, default_value_t = Mode::Corrupt)]
    mode: Mode,
    #[arg(long, value_enum, default_value_t = Integrity::Preserve)]
    integrity: Integrity,
}

#[derive(Args, Debug)]
struct ObjectArgs {
    #[arg(long, value_enum)]
    object: ObjectKind,
    #[arg(long, default_value = "primary", value_parser = ["primary", "metabox"])]
    space: String,
    #[arg(long)]
    nid: Option<u64>,
    #[arg(long, default_value_t = 0)]
    block: u64,
    #[arg(long, default_value_t = 0)]
    index: u32,
    #[arg(long, default_value_t = 0)]
    algorithm: u8,
}

#[derive(Args, Debug)]
struct FieldMutation {
    #[command(flatten)]
    common: Common,
    #[command(flatten)]
    object: ObjectArgs,
    #[arg(long)]
    field: String,
    #[arg(long, value_parser = parse_integer)]
    value: u64,
}

#[derive(Args, Debug)]
struct BitMutation {
    #[command(flatten)]
    common: Common,
    #[command(flatten)]
    object: ObjectArgs,
    #[arg(long)]
    field: String,
    #[arg(long, value_parser = parse_integer, default_value = "0")]
    set: u64,
    #[arg(long, value_parser = parse_integer, default_value = "0")]
    clear: u64,
}

#[derive(Args, Debug)]
struct ByteMutation {
    #[command(flatten)]
    common: Common,
    #[command(flatten)]
    object: ObjectArgs,
    #[arg(long)]
    field: String,
    #[arg(long)]
    hex: String,
}

#[derive(Args, Debug)]
struct RawMutation {
    #[command(flatten)]
    common: Common,
    #[arg(long, value_parser = parse_integer)]
    offset: u64,
    #[arg(long)]
    hex: String,
}

#[derive(Args, Debug)]
struct TruncateMutation {
    #[command(flatten)]
    common: Common,
    #[arg(long, value_parser = parse_integer)]
    length: u64,
}

pub fn inject(args: InjectArgs) -> Result<()> {
    let (common, intent) = match args.command {
        InjectCommand::Set(args) => {
            let object = object_ref(args.object)?;
            (
                args.common,
                MutationIntent::SetValue {
                    object,
                    field: args.field,
                    value: args.value,
                },
            )
        }
        InjectCommand::Bits(args) => {
            let object = object_ref(args.object)?;
            (
                args.common,
                MutationIntent::UpdateBits {
                    object,
                    field: args.field,
                    set: args.set,
                    clear: args.clear,
                },
            )
        }
        InjectCommand::Bytes(args) => {
            let object = object_ref(args.object)?;
            (
                args.common,
                MutationIntent::ReplaceFixedBytes {
                    object,
                    field: args.field,
                    bytes: parse_hex(&args.hex).map_err(anyhow::Error::msg)?,
                },
            )
        }
        InjectCommand::Raw(args) => (
            args.common,
            MutationIntent::PatchBytes {
                offset: args.offset,
                bytes: parse_hex(&args.hex).map_err(anyhow::Error::msg)?,
            },
        ),
        InjectCommand::Truncate(args) => (
            args.common,
            MutationIntent::TruncateImage {
                new_len: args.length,
            },
        ),
    };
    let bytes = fs::read(&common.image)
        .with_context(|| format!("failed to read {}", common.image.display()))?;
    let plan = plan(
        &bytes,
        &[intent],
        mode(common.mode),
        integrity(common.integrity),
    )?;
    print_sample(materialize(&common.image, &common.output_dir, &plan)?);
    Ok(())
}

fn object_ref(args: ObjectArgs) -> Result<ObjectRef> {
    match args.object {
        ObjectKind::Superblock => {
            if args.nid.is_some() {
                bail!("--nid is not valid for superblock");
            }
            Ok(ObjectRef::Superblock)
        }
        ObjectKind::Inode => Ok(ObjectRef::Inode {
            space: args.space,
            nid: args.nid.context("--nid is required for inode")?.to_string(),
        }),
        ObjectKind::Dirent => Ok(ObjectRef::Dirent {
            directory: args
                .nid
                .context("--nid is required for dirent")?
                .to_string(),
            block: args.block.to_string(),
            index: args.index,
        }),
        ObjectKind::SuperblockExtension => Ok(ObjectRef::SuperblockExtension {
            index: u8::try_from(args.index).context("--index exceeds u8")?,
        }),
        ObjectKind::DeviceSlot => Ok(ObjectRef::DeviceSlot {
            index: u16::try_from(args.index).context("--index exceeds u16")?,
        }),
        ObjectKind::Chunk => Ok(ObjectRef::Chunk {
            inode: args.nid.context("--nid is required for chunk")?.to_string(),
            index: args.index.to_string(),
        }),
        ObjectKind::XattrHeader => Ok(ObjectRef::XattrHeader {
            inode: args
                .nid
                .context("--nid is required for xattr header")?
                .to_string(),
        }),
        ObjectKind::SharedXattrId => Ok(ObjectRef::SharedXattrId {
            inode: args
                .nid
                .context("--nid is required for shared xattr ID")?
                .to_string(),
            index: args.index,
        }),
        ObjectKind::InlineXattr => Ok(ObjectRef::InlineXattr {
            inode: args
                .nid
                .context("--nid is required for inline xattr")?
                .to_string(),
            index: args.index,
        }),
        ObjectKind::XattrLongPrefix => Ok(ObjectRef::XattrLongPrefix {
            index: u8::try_from(args.index).context("--index exceeds u8")?,
        }),
        ObjectKind::CompressionConfig => Ok(ObjectRef::CompressionConfig {
            algorithm: args.algorithm,
        }),
        ObjectKind::CompressionMap => Ok(ObjectRef::CompressionMap {
            inode: args
                .nid
                .context("--nid is required for compression map")?
                .to_string(),
        }),
        ObjectKind::CompressionIndex => Ok(ObjectRef::CompressionIndex {
            inode: args
                .nid
                .context("--nid is required for compression index")?
                .to_string(),
            index: args.index.to_string(),
        }),
        ObjectKind::CompressionCompactPack => Ok(ObjectRef::CompressionCompactPack {
            inode: args
                .nid
                .context("--nid is required for compact pack")?
                .to_string(),
            index: args.index.to_string(),
        }),
        ObjectKind::CompressionExtent => Ok(ObjectRef::CompressionExtent {
            inode: args
                .nid
                .context("--nid is required for extent")?
                .to_string(),
            index: args.index.to_string(),
        }),
    }
}

fn mode(value: Mode) -> MutationMode {
    match value {
        Mode::Corrupt => MutationMode::Corrupt,
        Mode::Consistent => MutationMode::Consistent,
        Mode::Raw => MutationMode::Raw,
    }
}
fn integrity(value: Integrity) -> IntegrityPolicy {
    match value {
        Integrity::Preserve => IntegrityPolicy::Preserve,
        Integrity::Recalculate => IntegrityPolicy::Recalculate,
        Integrity::Invalidate => IntegrityPolicy::Invalidate,
    }
}
fn print_sample(sample: PublishedSample) {
    println!("sample: {}", sample.output_sha256);
    println!("image: {}", sample.image.display());
    println!("manifest: {}", sample.manifest.display());
}
fn parse_integer(value: &str) -> Result<u64, String> {
    value.strip_prefix("0x").map_or_else(
        || {
            value
                .parse()
                .map_err(|error: std::num::ParseIntError| error.to_string())
        },
        |hex| u64::from_str_radix(hex, 16).map_err(|error| error.to_string()),
    )
}
fn parse_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("hex must have even length".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|error| error.to_string())?;
            u8::from_str_radix(text, 16).map_err(|error| error.to_string())
        })
        .collect()
}
