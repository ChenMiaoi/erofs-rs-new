use std::fs;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand, ValueEnum};
use erofs_format::{
    SliceReader,
    locator::{
        DecodedValue, FieldOccurrence, LocateError, Locator, MetadataSpace, ObjectRef, ParseMode,
    },
    schema::{Encoding, FIELDS, Predicate, SCHEMA_IDENTITY, StructureId, field_by_id},
};

#[derive(Args, Debug)]
pub struct FieldArgs {
    #[command(subcommand)]
    command: FieldCommand,
}

#[derive(Subcommand, Debug)]
enum FieldCommand {
    /// List the fields compiled into the pinned ABI schema.
    List(ListArgs),
    /// Locate one field occurrence in a local image.
    Locate(LocateArgs),
}

#[derive(Args, Debug)]
struct ListArgs {
    /// List the compiled ABI schema (accepted for protocol compatibility).
    #[arg(long)]
    schema: bool,
    /// Emit one versioned JSON document.
    #[arg(long)]
    json: bool,
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
    Strict,
    Tolerant,
}

#[derive(Args, Debug)]
struct LocateArgs {
    /// Local EROFS image.
    image: String,
    /// Canonical object kind.
    #[arg(long, value_enum)]
    object: ObjectKind,
    /// Stable field ID, such as `erofs.inode.compact.i_format`.
    #[arg(long)]
    field: String,
    /// Metadata space for inode objects.
    #[arg(long, default_value = "primary", value_parser = ["primary", "metabox"])]
    space: String,
    /// Primary inode NID, or directory inode NID for a dirent.
    #[arg(long)]
    nid: Option<u64>,
    /// Logical directory block index.
    #[arg(long, default_value_t = 0)]
    block: u64,
    /// Dirent index within the directory block.
    #[arg(long, default_value_t = 0)]
    index: u32,
    /// Compression algorithm ID or other object-specific selector.
    #[arg(long, default_value_t = 0)]
    algorithm: u8,
    /// Parent-structure validation policy.
    #[arg(long, value_enum, default_value_t = Mode::Strict)]
    mode: Mode,
    /// Emit one versioned JSON document.
    #[arg(long)]
    json: bool,
}

pub fn field(args: FieldArgs) -> Result<()> {
    match args.command {
        FieldCommand::List(args) => list(args),
        FieldCommand::Locate(args) => locate(args),
    }
}

fn list(args: ListArgs) -> Result<()> {
    let _ = args.schema;
    if args.json {
        print!(
            "{{\"schema\":\"erofs-field-list/v1\",\"abi\":{{\"api\":\"{}\",\"linux_commit\":\"{}\",\"source_header\":\"{}\",\"digest\":\"{}\"}},\"fields\":[",
            SCHEMA_IDENTITY.api,
            SCHEMA_IDENTITY.linux_commit,
            SCHEMA_IDENTITY.source_header,
            SCHEMA_IDENTITY.digest
        );
        for (index, field) in FIELDS.iter().enumerate() {
            if index != 0 {
                print!(",");
            }
            print!(
                "{{\"id\":\"{}\",\"structure\":\"{}\",\"offset\":\"{}\",\"length\":\"{}\",\"encoding\":\"{}\",\"predicate\":\"{}\",\"source_member\":\"{}\"}}",
                field.id,
                structure_name(field.structure),
                field.storage.offset,
                field.storage.len,
                encoding_name(field.encoding),
                predicate_name(field.presence),
                field.member
            );
        }
        println!("]}}");
    } else {
        for field in FIELDS {
            println!(
                "{}\t{}\t{}+{}\t{}\t{}",
                field.id,
                structure_name(field.structure),
                field.storage.offset,
                field.storage.len,
                encoding_name(field.encoding),
                predicate_name(field.presence)
            );
        }
    }
    Ok(())
}

fn locate(args: LocateArgs) -> Result<()> {
    let bytes = fs::read(&args.image).with_context(|| format!("failed to read {}", args.image))?;
    let reader = SliceReader::new(&bytes);
    let mode = match args.mode {
        Mode::Strict => ParseMode::Strict,
        Mode::Tolerant => ParseMode::Tolerant,
    };
    let locator = Locator::with_mode(&reader, mode).map_err(format_locator_error)?;
    let space = if args.space == "metabox" {
        MetadataSpace::Metabox
    } else {
        MetadataSpace::Primary
    };
    let field =
        field_by_id(&args.field).ok_or_else(|| anyhow!("unknown field ID: {}", args.field))?;
    let object = match args.object {
        ObjectKind::Superblock => {
            if args.nid.is_some() {
                bail!("--nid is not valid for a superblock object");
            }
            ObjectRef::Superblock
        }
        ObjectKind::Inode => ObjectRef::Inode {
            space,
            nid: args.nid.context("--nid is required for an inode object")?,
        },
        ObjectKind::Dirent => ObjectRef::Dirent {
            directory: args.nid.context("--nid is required for a dirent object")?,
            block: args.block,
            index: args.index,
        },
        ObjectKind::SuperblockExtension => ObjectRef::SuperblockExtension {
            index: u8::try_from(args.index).context("--index exceeds u8")?,
        },
        ObjectKind::DeviceSlot => ObjectRef::DeviceSlot {
            index: u16::try_from(args.index).context("--index exceeds u16")?,
        },
        ObjectKind::Chunk => ObjectRef::Chunk {
            inode: args.nid.context("--nid is required for chunk")?,
            index: u64::from(args.index),
        },
        ObjectKind::XattrHeader => ObjectRef::XattrHeader {
            inode: args.nid.context("--nid is required for xattr header")?,
        },
        ObjectKind::SharedXattrId => ObjectRef::SharedXattrId {
            inode: args.nid.context("--nid is required for shared xattr ID")?,
            index: args.index,
        },
        ObjectKind::InlineXattr => ObjectRef::InlineXattr {
            inode: args.nid.context("--nid is required for inline xattr")?,
            index: args.index,
        },
        ObjectKind::XattrLongPrefix => ObjectRef::XattrLongPrefix {
            index: u8::try_from(args.index).context("--index exceeds u8")?,
        },
        ObjectKind::CompressionConfig => ObjectRef::CompressionConfig {
            algorithm: args.algorithm,
        },
        ObjectKind::CompressionMap => ObjectRef::CompressionMap {
            inode: args.nid.context("--nid is required for compression map")?,
        },
        ObjectKind::CompressionIndex => ObjectRef::CompressionIndex {
            inode: args
                .nid
                .context("--nid is required for compression index")?,
            index: u64::from(args.index),
        },
        ObjectKind::CompressionCompactPack => ObjectRef::CompressionCompactPack {
            inode: args.nid.context("--nid is required for compact pack")?,
            index: u64::from(args.index),
        },
        ObjectKind::CompressionExtent => ObjectRef::CompressionExtent {
            inode: args.nid.context("--nid is required for extent")?,
            index: u64::from(args.index),
        },
    };
    let occurrence = locator
        .locate(object, field)
        .map_err(format_locator_error)?;
    if args.json {
        print_occurrence_json(&occurrence);
    } else {
        println!("field: {}", occurrence.field.id);
        println!("object: {}", object_name(occurrence.object));
        println!("span: {}+{}", occurrence.span.offset, occurrence.span.len);
        println!(
            "raw: {}",
            hex(&occurrence.raw[..usize::from(occurrence.raw_len)])
        );
        println!("value: {}", display_value(occurrence.value));
    }
    Ok(())
}

fn print_occurrence_json(occurrence: &FieldOccurrence) {
    print!(
        "{{\"schema\":\"erofs-field-occurrence/v1\",\"abi_digest\":\"{}\",\"field\":\"{}\",\"object\":{},\"span\":{{\"offset\":\"{}\",\"length\":\"{}\"}},\"raw_hex\":\"{}\",\"value\":{},\"predicate\":\"{}\",\"provenance\":[",
        SCHEMA_IDENTITY.digest,
        occurrence.field.id,
        object_json(occurrence.object),
        occurrence.span.offset,
        occurrence.span.len,
        hex(&occurrence.raw[..usize::from(occurrence.raw_len)]),
        value_json(occurrence.value),
        predicate_name(occurrence.field.presence)
    );
    let mut first = true;
    for dependency in occurrence.provenance.iter().flatten() {
        if !first {
            print!(",");
        }
        first = false;
        print!(
            "{{\"field\":\"{}\",\"span\":{{\"offset\":\"{}\",\"length\":\"{}\"}},\"value\":\"{}\"}}",
            dependency.field, dependency.span.offset, dependency.span.len, dependency.value
        );
    }
    println!("]}}");
}

fn object_json(object: ObjectRef) -> String {
    match object {
        ObjectRef::Superblock => "{\"kind\":\"superblock\"}".into(),
        ObjectRef::Inode { nid, .. } => {
            format!("{{\"kind\":\"inode\",\"space\":\"primary\",\"nid\":\"{nid}\"}}")
        }
        ObjectRef::Dirent {
            directory,
            block,
            index,
        } => format!(
            "{{\"kind\":\"dirent\",\"directory\":{{\"space\":\"primary\",\"nid\":\"{directory}\"}},\"block\":\"{block}\",\"index\":{index}}}"
        ),
        ObjectRef::SuperblockExtension { index } => {
            format!("{{\"kind\":\"superblock_extension\",\"index\":{index}}}")
        }
        ObjectRef::DeviceSlot { index } => {
            format!("{{\"kind\":\"device_slot\",\"index\":{index}}}")
        }
        ObjectRef::Chunk { inode, index } => {
            format!("{{\"kind\":\"chunk\",\"inode\":\"{inode}\",\"index\":\"{index}\"}}")
        }
        ObjectRef::XattrHeader { inode } => {
            format!("{{\"kind\":\"xattr_header\",\"inode\":\"{inode}\"}}")
        }
        ObjectRef::SharedXattrId { inode, index } => {
            format!("{{\"kind\":\"shared_xattr_id\",\"inode\":\"{inode}\",\"index\":{index}}}")
        }
        ObjectRef::InlineXattr { inode, index } => {
            format!("{{\"kind\":\"inline_xattr\",\"inode\":\"{inode}\",\"index\":{index}}}")
        }
        ObjectRef::XattrLongPrefix { index } => {
            format!("{{\"kind\":\"xattr_long_prefix\",\"index\":{index}}}")
        }
        ObjectRef::CompressionConfig { algorithm } => {
            format!("{{\"kind\":\"compression_config\",\"algorithm\":{algorithm}}}")
        }
        ObjectRef::CompressionMap { inode } => {
            format!("{{\"kind\":\"compression_map\",\"inode\":\"{inode}\"}}")
        }
        ObjectRef::CompressionIndex { inode, index } => format!(
            "{{\"kind\":\"compression_index\",\"inode\":\"{inode}\",\"index\":\"{index}\"}}"
        ),
        ObjectRef::CompressionCompactPack { inode, index } => format!(
            "{{\"kind\":\"compression_compact_pack\",\"inode\":\"{inode}\",\"index\":\"{index}\"}}"
        ),
        ObjectRef::CompressionExtent { inode, index } => format!(
            "{{\"kind\":\"compression_extent\",\"inode\":\"{inode}\",\"index\":\"{index}\"}}"
        ),
    }
}

fn object_name(object: ObjectRef) -> String {
    match object {
        ObjectRef::Superblock => "superblock".into(),
        ObjectRef::Inode { nid, .. } => format!("inode(primary,{nid})"),
        ObjectRef::Dirent {
            directory,
            block,
            index,
        } => {
            format!("dirent(directory={directory},block={block},index={index})")
        }
        ObjectRef::SuperblockExtension { index } => format!("superblock-extension({index})"),
        ObjectRef::DeviceSlot { index } => format!("device-slot({index})"),
        ObjectRef::Chunk { inode, index } => format!("chunk(inode={inode},index={index})"),
        ObjectRef::XattrHeader { inode } => format!("xattr-header(inode={inode})"),
        ObjectRef::SharedXattrId { inode, index } => {
            format!("shared-xattr-id(inode={inode},index={index})")
        }
        ObjectRef::InlineXattr { inode, index } => {
            format!("inline-xattr(inode={inode},index={index})")
        }
        ObjectRef::XattrLongPrefix { index } => format!("xattr-long-prefix({index})"),
        ObjectRef::CompressionConfig { algorithm } => format!("compression-config({algorithm})"),
        ObjectRef::CompressionMap { inode } => format!("compression-map(inode={inode})"),
        ObjectRef::CompressionIndex { inode, index } => {
            format!("compression-index(inode={inode},index={index})")
        }
        ObjectRef::CompressionCompactPack { inode, index } => {
            format!("compression-compact-pack(inode={inode},index={index})")
        }
        ObjectRef::CompressionExtent { inode, index } => {
            format!("compression-extent(inode={inode},index={index})")
        }
    }
}

fn format_locator_error<E: std::fmt::Debug>(error: LocateError<E>) -> anyhow::Error {
    match error {
        LocateError::Read(error) => anyhow!("image read failed: {error:?}"),
        LocateError::Overflow => {
            anyhow!("locator diagnostic overflow: address arithmetic overflowed")
        }
        LocateError::OutOfBounds { span, image_len } => anyhow!(
            "locator diagnostic out_of_bounds: span {}+{} exceeds image length {}",
            span.offset,
            span.len,
            image_len
        ),
        LocateError::ObjectMismatch {
            field_structure,
            object,
        } => anyhow!(
            "locator diagnostic object_mismatch: field structure {field_structure:?}, object {object:?}"
        ),
        LocateError::AbsentByFeature { field, predicate } => {
            anyhow!("locator diagnostic absent_by_feature: field {field}, predicate {predicate:?}")
        }
        LocateError::UnresolvedParent { object, reason } => {
            anyhow!("locator diagnostic unresolved_parent: object {object:?}, reason {reason}")
        }
        LocateError::InvalidStructure { object, reason } => {
            anyhow!("locator diagnostic invalid_structure: object {object:?}, reason {reason}")
        }
        LocateError::UnsupportedCapability(capability) => {
            anyhow!("locator diagnostic unsupported_capability: {capability:?}")
        }
    }
}

fn structure_name(value: StructureId) -> &'static str {
    match value {
        StructureId::Superblock => "superblock",
        StructureId::CompactInode => "compact_inode",
        StructureId::ExtendedInode => "extended_inode",
        StructureId::Dirent => "dirent",
        StructureId::SuperblockExtension => "superblock_extension",
        StructureId::DeviceSlot => "device_slot",
        StructureId::ChunkEntry => "chunk_entry",
        StructureId::XattrHeader => "xattr_header",
        StructureId::SharedXattrId => "shared_xattr_id",
        StructureId::XattrEntry => "xattr_entry",
        StructureId::XattrLongPrefix => "xattr_long_prefix",
        StructureId::CompressionConfig => "compression_config",
        StructureId::CompressionMap => "compression_map",
        StructureId::CompressionIndex => "compression_index",
        StructureId::CompressionCompactPack => "compression_compact_pack",
        StructureId::CompressionExtent => "compression_extent",
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

fn predicate_name(value: Predicate) -> &'static str {
    match value {
        Predicate::Always => "always",
        Predicate::Without48Bit => "without-48bit",
        Predicate::With48Bit => "with-48bit",
        Predicate::WithoutCompressionConfig => "without-compression-config",
        Predicate::WithCompressionConfig => "with-compression-config",
        Predicate::Superblock144 => "superblock-size-at-least-144",
        Predicate::WithMetabox => "with-metabox",
        Predicate::WithXattrPrefixes => "with-xattr-prefixes",
        Predicate::WithDeviceTable => "with-device-table",
        Predicate::Dynamic => "dynamic",
    }
}

fn display_value(value: DecodedValue) -> String {
    match value {
        DecodedValue::Unsigned(value) => value.to_string(),
        DecodedValue::Bytes { bytes, len } => hex(&bytes[..usize::from(len)]),
    }
}

fn value_json(value: DecodedValue) -> String {
    match value {
        DecodedValue::Unsigned(value) => format!("{{\"kind\":\"unsigned\",\"value\":\"{value}\"}}"),
        DecodedValue::Bytes { bytes, len } => format!(
            "{{\"kind\":\"bytes\",\"hex\":\"{}\"}}",
            hex(&bytes[..usize::from(len)])
        ),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}
