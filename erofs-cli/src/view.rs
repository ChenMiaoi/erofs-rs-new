//! Visual field-level image inspector.
//!
//! `erofs-cli view <image>` renders the on-disk structure of an EROFS image:
//! a block-level usage map, the object tree (superblock plus every inode
//! found by walking the filesystem), the schema fields of the selected
//! object with offsets and decoded values, and a hex dump of the selected
//! span. On a non-terminal stdout (or with `--no-tui`) the same model is
//! printed as plain text.

use std::collections::HashSet;
use std::io::{self, IsTerminal};
use std::time::Duration;
use std::{fs, path::Path};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use erofs_format::{
    SliceReader, Span,
    locator::{DecodedValue, Locator, MetadataSpace, ObjectRef, ParseMode},
    schema::FIELDS,
};
use erofs_rs::backend::SliceImage;
use erofs_rs::{EroFS, types::Layout};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout as Split, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span as Text},
    widgets::{
        Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Row, Table,
        TableState,
    },
};

use crate::field::{display_value, hex};

const BG: Color = Color::Rgb(13, 16, 22);
const SURFACE: Color = Color::Rgb(18, 22, 29);
const TEXT: Color = Color::Rgb(226, 232, 240);
const MUTED: Color = Color::Rgb(148, 163, 184);
const BORDER: Color = Color::Rgb(71, 85, 105);
const ACCENT: Color = Color::Rgb(251, 191, 36);
const SELECTED_BG: Color = Color::Rgb(45, 55, 72);

#[derive(Args, Debug)]
pub struct ViewArgs {
    /// EROFS image to inspect.
    image: String,
    /// Print a plain-text rendering instead of opening the TUI.
    #[arg(long)]
    no_tui: bool,
    /// Structural validation policy while locating fields.
    #[arg(long, value_enum, default_value = "tolerant")]
    mode: ViewMode,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ViewMode {
    Strict,
    Tolerant,
}

/// Block usage classification for the map strip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockKind {
    Unused,
    Superblock,
    Metadata,
    DirData,
    FileData,
}

/// The meaning of one physical byte range owned by an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExtentRole {
    Superblock,
    Inode,
    Xattr,
    Data,
    InlineData,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObjectKind {
    Superblock,
    Directory,
    Symlink,
    File,
}

impl ObjectKind {
    fn icon(self) -> &'static str {
        match self {
            Self::Superblock => "◆",
            Self::Directory => "▾",
            Self::Symlink => "↗",
            Self::File => "•",
        }
    }

    fn color(self) -> Color {
        match self {
            Self::Superblock => Color::LightMagenta,
            Self::Directory => Color::LightGreen,
            Self::Symlink => Color::LightCyan,
            Self::File => Color::LightBlue,
        }
    }
}

impl ExtentRole {
    fn label(self) -> &'static str {
        match self {
            Self::Superblock => "superblock",
            Self::Inode => "inode",
            Self::Xattr => "xattr",
            Self::Data => "data",
            Self::InlineData => "inline-tail",
        }
    }

    fn color(self, is_dir: bool) -> Color {
        match self {
            Self::Superblock => Color::Magenta,
            Self::Inode | Self::Xattr => Color::Cyan,
            Self::Data | Self::InlineData if is_dir => Color::Green,
            Self::Data | Self::InlineData => Color::Blue,
        }
    }
}

/// An exact physical range in the image, optionally mapped from a logical
/// file offset.
#[derive(Clone, Debug)]
struct PhysicalExtent {
    role: ExtentRole,
    span: Span,
    logical_offset: Option<u64>,
}

#[derive(Clone, Debug)]
struct RelatedObject {
    label: String,
    object: ObjectRef,
}

impl BlockKind {
    fn color(self) -> Color {
        match self {
            Self::Unused => Color::Gray,
            Self::Superblock => Color::Magenta,
            Self::Metadata => Color::Cyan,
            Self::DirData => Color::Green,
            Self::FileData => Color::Blue,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Unused => "unused",
            Self::Superblock => "superblock",
            Self::Metadata => "metadata",
            Self::DirData => "dir-data",
            Self::FileData => "file-data",
        }
    }
}

/// One row of the object tree.
struct Node {
    depth: usize,
    label: String,
    detail: String,
    object: ObjectRef,
    span: Span,
    is_dir: bool,
    extents: Vec<PhysicalExtent>,
    placement_note: Option<String>,
    kind: ObjectKind,
    data_size: Option<u64>,
    layout_name: Option<&'static str>,
    layout: Option<Layout>,
    raw_block_addr: Option<u32>,
    related: Vec<RelatedObject>,
}

/// One located schema field of the selected object.
struct FieldRow {
    id: &'static str,
    span: Span,
    raw_hex: String,
    decoded: DecodedValue,
}

/// Everything the viewer knows about an image, independent of rendering.
struct ImageModel {
    bytes: Vec<u8>,
    block_size: u64,
    nodes: Vec<Node>,
    block_kinds: Vec<BlockKind>,
    block_owners: Vec<Vec<usize>>,
    walk_warning: Option<String>,
}

impl ImageModel {
    /// Builds the model from raw image bytes.
    ///
    /// The superblock must parse; filesystem-tree and data-block information
    /// is best-effort so that malformed (e.g. fuzzed) images still render.
    fn build(bytes: Vec<u8>, mode: ParseMode) -> Result<Self> {
        let reader = SliceReader::new(&bytes);
        let locator = Locator::with_mode(&reader, mode)
            .map_err(|error| anyhow::anyhow!("cannot parse superblock: {error:?}"))?;
        let sb = locator.superblock();
        let block_size = 1u64
            .checked_shl(u32::from(sb.blkszbits))
            .filter(|size| (512..=(1u64 << 24)).contains(size))
            .context("invalid block-size shift in superblock")?;

        let block_count = (bytes.len() as u64).div_ceil(block_size) as usize;
        let mut block_kinds = vec![BlockKind::Unused; block_count];
        let super_block = (erofs_format::SUPERBLOCK_OFFSET / block_size) as usize;
        if let Some(kind) = block_kinds.get_mut(super_block) {
            *kind = BlockKind::Superblock;
        }

        let superblock_span = Span::new(
            erofs_format::SUPERBLOCK_OFFSET,
            erofs_format::SUPERBLOCK_BASE_SIZE
                + u64::from(sb.ext_slots) * erofs_format::SUPERBLOCK_EXTSLOT_SIZE,
        )
        .map_err(|_| anyhow::anyhow!("superblock span overflow"))?;
        let mut nodes = vec![Node {
            depth: 0,
            label: "superblock".to_string(),
            detail: format!(
                "blksz={} incompat={:#x} compat={:#x}",
                block_size, sb.feature_incompat, sb.feature_compat
            ),
            object: ObjectRef::Superblock,
            span: superblock_span,
            is_dir: false,
            extents: vec![PhysicalExtent {
                role: ExtentRole::Superblock,
                span: superblock_span,
                logical_offset: None,
            }],
            placement_note: None,
            kind: ObjectKind::Superblock,
            data_size: None,
            layout_name: None,
            layout: None,
            raw_block_addr: None,
            related: Vec::new(),
        }];

        let mut walk_warning = None;
        match EroFS::new(SliceImage::new(&bytes)) {
            Ok(image) => {
                if let Err(error) = Self::walk(
                    &image,
                    sb.meta_blkaddr,
                    sb.blkszbits,
                    block_size,
                    &mut nodes,
                    &mut block_kinds,
                ) {
                    walk_warning = Some(error);
                }
            }
            Err(error) => walk_warning = Some(format!("filesystem tree unavailable: {error}")),
        }

        let mut model = Self {
            bytes,
            block_size,
            nodes,
            block_kinds,
            block_owners: vec![Vec::new(); block_count],
            walk_warning,
        };
        model.discover_structures_and_mappings(mode);
        model.rebuild_block_owners();
        Ok(model)
    }

    /// Appends one tree row per inode, marking metadata and data blocks.
    fn walk(
        image: &EroFS<SliceImage<'_>>,
        meta_blkaddr: u32,
        blkszbits: u8,
        block_size: u64,
        nodes: &mut Vec<Node>,
        block_kinds: &mut [BlockKind],
    ) -> std::result::Result<(), String> {
        let mut warning = None;
        let root_nid = u64::from(image.super_block().root_nid);

        let mut push_inode = |depth: usize,
                              label: String,
                              inode: &erofs_rs::types::Inode,
                              nodes: &mut Vec<Node>| {
            let nid = inode.id();
            let is_dir = inode.is_dir();
            let object_kind = if is_dir {
                ObjectKind::Directory
            } else if inode.is_symlink() {
                ObjectKind::Symlink
            } else {
                ObjectKind::File
            };
            let kind = match object_kind {
                ObjectKind::Directory => "dir ",
                ObjectKind::Symlink => "link",
                ObjectKind::File => "file",
                ObjectKind::Superblock => unreachable!(),
            };
            if let Ok(offset) = erofs_format::primary_inode_offset(meta_blkaddr, blkszbits, nid) {
                let inode_size = inode.size() as u64;
                let span = Span::new(offset, inode_size);
                if let Ok(span) = span {
                    mark_blocks(block_kinds, span, block_size, BlockKind::Metadata);
                    let data_size = inode.data_size() as u64;
                    let blkaddr = inode.raw_block_addr();
                    let layout = inode.layout().ok();
                    let mut extents = vec![PhysicalExtent {
                        role: ExtentRole::Inode,
                        span,
                        logical_offset: None,
                    }];

                    let xattr_size = inode.xattr_size() as u64;
                    if xattr_size > 0
                        && let Ok(xattr_span) = Span::new(offset + inode_size, xattr_size)
                    {
                        mark_blocks(block_kinds, xattr_span, block_size, BlockKind::Metadata);
                        extents.push(PhysicalExtent {
                            role: ExtentRole::Xattr,
                            span: xattr_span,
                            logical_offset: None,
                        });
                    }

                    if data_size > 0 && blkaddr != u32::MAX {
                        let mut add_data_extent =
                            |role: ExtentRole, physical: u64, logical: u64, len: u64| {
                                if len == 0 {
                                    return;
                                }
                                if let Ok(data_span) = Span::new(physical, len) {
                                    mark_blocks(
                                        block_kinds,
                                        data_span,
                                        block_size,
                                        if is_dir {
                                            BlockKind::DirData
                                        } else {
                                            BlockKind::FileData
                                        },
                                    );
                                    extents.push(PhysicalExtent {
                                        role,
                                        span: data_span,
                                        logical_offset: Some(logical),
                                    });
                                }
                            };
                        match layout {
                            Some(Layout::FlatPlain) => add_data_extent(
                                ExtentRole::Data,
                                u64::from(blkaddr) * block_size,
                                0,
                                data_size,
                            ),
                            Some(Layout::FlatInline) => {
                                let block_data = data_size / block_size * block_size;
                                add_data_extent(
                                    ExtentRole::Data,
                                    u64::from(blkaddr) * block_size,
                                    0,
                                    block_data,
                                );
                                let tail_size = data_size % block_size;
                                add_data_extent(
                                    ExtentRole::InlineData,
                                    offset + inode_size + xattr_size,
                                    block_data,
                                    tail_size,
                                );
                            }
                            _ => {}
                        }
                    }
                    let layout_name = match layout {
                        Some(Layout::FlatPlain) => "plain",
                        Some(Layout::FlatInline) => "inline",
                        Some(Layout::CompressedFull) => "compressed-full",
                        Some(Layout::CompressedCompact) => "compressed-compact",
                        Some(Layout::ChunkBased) => "chunked",
                        None => "unknown-layout",
                    };
                    let placement_note = if data_size == 0 {
                        None
                    } else if blkaddr == u32::MAX {
                        Some("payload block address is unavailable".to_string())
                    } else if matches!(
                        layout,
                        Some(Layout::CompressedFull | Layout::CompressedCompact)
                    ) {
                        Some(
                            "compressed payload mapping is not exposed by the current reader"
                                .to_string(),
                        )
                    } else if layout == Some(Layout::ChunkBased) {
                        Some(
                            "chunk-table payload mapping is not exposed by the current reader"
                                .to_string(),
                        )
                    } else if layout.is_none() {
                        Some("payload layout could not be decoded".to_string())
                    } else {
                        None
                    };
                    nodes.push(Node {
                        depth,
                        label,
                        detail: format!("{kind} nid={nid} size={data_size} layout={layout_name}"),
                        object: ObjectRef::Inode {
                            space: MetadataSpace::Primary,
                            nid,
                        },
                        span,
                        is_dir,
                        extents,
                        placement_note,
                        kind: object_kind,
                        data_size: Some(data_size),
                        layout_name: Some(layout_name),
                        layout,
                        raw_block_addr: Some(blkaddr),
                        related: Vec::new(),
                    });
                }
            }
        };

        if let Ok(root) = image.get_inode(root_nid) {
            push_inode(0, "/".to_string(), &root, nodes);
        }
        match image.walk_dir("/") {
            Ok(walker) => {
                for entry in walker {
                    match entry {
                        Ok(entry) => push_inode(
                            entry.depth,
                            entry.dir_entry.path().to_string_lossy().into_owned(),
                            &entry.inode,
                            nodes,
                        ),
                        Err(error) => {
                            warning.get_or_insert_with(|| format!("walk stopped early: {error}"));
                            break;
                        }
                    }
                }
            }
            Err(error) => {
                warning = Some(format!("cannot walk root: {error}"));
            }
        }
        warning.map_or(Ok(()), Err)
    }

    /// Locates every schema field applicable to `object`.
    fn fields(&self, object: ObjectRef, mode: ParseMode) -> Vec<FieldRow> {
        locate_fields(&self.bytes, mode, object)
    }

    fn discover_structures_and_mappings(&mut self, mode: ParseMode) {
        let bytes = &self.bytes;
        let block_size = self.block_size;
        let sb = Locator::with_mode(&SliceReader::new(bytes), mode)
            .ok()
            .map(|locator| locator.superblock());

        if let Some(sb) = sb {
            for index in 0..sb.ext_slots {
                self.nodes[0].related.push(RelatedObject {
                    label: format!("super extension [{index}]"),
                    object: ObjectRef::SuperblockExtension { index },
                });
            }
            for index in 0..sb.extra_devices {
                self.nodes[0].related.push(RelatedObject {
                    label: format!("device slot [{index}]"),
                    object: ObjectRef::DeviceSlot { index },
                });
            }
            for index in 0..sb.xattr_prefix_count {
                self.nodes[0].related.push(RelatedObject {
                    label: format!("xattr prefix [{index}]"),
                    object: ObjectRef::XattrLongPrefix { index },
                });
            }
            for algorithm in 0..4 {
                let object = ObjectRef::CompressionConfig { algorithm };
                if !locate_fields(bytes, mode, object).is_empty() {
                    let name = ["lz4", "lzma", "deflate", "zstd"][usize::from(algorithm)];
                    self.nodes[0].related.push(RelatedObject {
                        label: format!("compression config · {name}"),
                        object,
                    });
                }
            }
        }

        for node in self.nodes.iter_mut().skip(1) {
            let ObjectRef::Inode { nid, .. } = node.object else {
                continue;
            };
            if node.is_dir {
                let blocks = node.data_size.unwrap_or(0).div_ceil(block_size);
                for block in 0..blocks {
                    for index in 0..(block_size / 12).min(4096) as u32 {
                        if !add_related(
                            node,
                            bytes,
                            mode,
                            format!("dirent b{block}[{index}]"),
                            ObjectRef::Dirent {
                                directory: nid,
                                block,
                                index,
                            },
                        ) {
                            break;
                        }
                    }
                }
            }

            if add_related(
                node,
                bytes,
                mode,
                "xattr header".to_string(),
                ObjectRef::XattrHeader { inode: nid },
            ) {
                for index in 0..256 {
                    if !add_related(
                        node,
                        bytes,
                        mode,
                        format!("shared xattr [{index}]"),
                        ObjectRef::SharedXattrId { inode: nid, index },
                    ) {
                        break;
                    }
                }
                for index in 0..256 {
                    let object = ObjectRef::InlineXattr { inode: nid, index };
                    let fields = locate_fields(bytes, mode, object);
                    if fields.is_empty()
                        || (decoded_field(&fields, "erofs.xattr.entry.name_len") == Some(0)
                            && decoded_field(&fields, "erofs.xattr.entry.value_size") == Some(0))
                    {
                        break;
                    }
                    node.related.push(RelatedObject {
                        label: format!("inline xattr [{index}]"),
                        object,
                    });
                }
            }

            match node.layout {
                Some(Layout::ChunkBased) => {
                    let raw = node.raw_block_addr.unwrap_or(0);
                    let chunk_bits =
                        u32::from((raw as u16) & erofs_format::CHUNK_FORMAT_BLKBITS_MASK)
                            + block_size.trailing_zeros();
                    let Some(chunk_size) = 1_u64.checked_shl(chunk_bits) else {
                        continue;
                    };
                    let chunks = node.data_size.unwrap_or(0).div_ceil(chunk_size);
                    let indexed = raw as u16 & erofs_format::CHUNK_FORMAT_INDEXES != 0;
                    let mut mapped = 0usize;
                    let mut external = 0usize;
                    for index in 0..chunks.min(1_000_000) {
                        let object = ObjectRef::Chunk { inode: nid, index };
                        let fields = locate_fields(bytes, mode, object);
                        if fields.is_empty() {
                            break;
                        }
                        node.related.push(RelatedObject {
                            label: format!("chunk [{index}]"),
                            object,
                        });
                        let device = decoded_field(&fields, "erofs.chunk.device_id").unwrap_or(0);
                        let block = if indexed {
                            decoded_field(&fields, "erofs.chunk.startblk_lo").map(|low| {
                                low | (decoded_field(&fields, "erofs.chunk.startblk_hi")
                                    .unwrap_or(0)
                                    << 32)
                            })
                        } else {
                            decoded_field(&fields, "erofs.chunk.block")
                        };
                        if device != 0 {
                            external += 1;
                        } else if let Some(block) = block
                            && block > 0
                            && block != u64::from(u32::MAX)
                        {
                            let len = chunk_size.min(
                                node.data_size
                                    .unwrap_or(0)
                                    .saturating_sub(index * chunk_size),
                            );
                            if let Ok(span) = Span::new(block.saturating_mul(block_size), len) {
                                node.extents.push(PhysicalExtent {
                                    role: ExtentRole::Data,
                                    span,
                                    logical_offset: Some(index * chunk_size),
                                });
                                mapped += 1;
                            }
                        }
                    }
                    node.placement_note = if external > 0 {
                        Some(format!(
                            "{external} chunk(s) live on external devices; {mapped} local chunk(s) mapped"
                        ))
                    } else if mapped == chunks as usize {
                        None
                    } else {
                        Some(format!("mapped {mapped} of {chunks} chunks"))
                    };
                }
                Some(Layout::CompressedFull | Layout::CompressedCompact) => {
                    let map = ObjectRef::CompressionMap { inode: nid };
                    let fields = locate_fields(bytes, mode, map);
                    if !fields.is_empty() {
                        node.related.push(RelatedObject {
                            label: "compression map".to_string(),
                            object: map,
                        });
                    }
                    let advise =
                        decoded_field(&fields, "erofs.compression.map.advise").unwrap_or(0);
                    if advise & 1 != 0 {
                        let count = decoded_field(&fields, "erofs.compression.map.extents_lo")
                            .unwrap_or(0)
                            | (decoded_field(&fields, "erofs.compression.map.extents_hi")
                                .unwrap_or(0)
                                << 32);
                        for index in 0..count.min(1_000_000) {
                            let object = ObjectRef::CompressionExtent { inode: nid, index };
                            let extent_fields = locate_fields(bytes, mode, object);
                            if extent_fields.is_empty() {
                                break;
                            }
                            node.related.push(RelatedObject {
                                label: format!("compression extent [{index}]"),
                                object,
                            });
                            let plen =
                                decoded_field(&extent_fields, "erofs.compression.extent.plen")
                                    .unwrap_or(0)
                                    & 0x1f_ffff;
                            let physical =
                                decoded_field(&extent_fields, "erofs.compression.extent.pstart_lo")
                                    .unwrap_or(0)
                                    | (decoded_field(
                                        &extent_fields,
                                        "erofs.compression.extent.pstart_hi",
                                    )
                                    .unwrap_or(0)
                                        << 32);
                            let logical =
                                decoded_field(&extent_fields, "erofs.compression.extent.lstart_lo")
                                    .unwrap_or(0)
                                    | (decoded_field(
                                        &extent_fields,
                                        "erofs.compression.extent.lstart_hi",
                                    )
                                    .unwrap_or(0)
                                        << 32);
                            if plen > 0
                                && let Ok(span) = Span::new(physical, plen)
                            {
                                node.extents.push(PhysicalExtent {
                                    role: ExtentRole::Data,
                                    span,
                                    logical_offset: Some(logical),
                                });
                            }
                        }
                        node.placement_note = None;
                    } else if node.layout == Some(Layout::CompressedFull) {
                        let cluster_bits =
                            decoded_field(&fields, "erofs.compression.map.clusterbits")
                                .unwrap_or(0)
                                & 0x0f;
                        let cluster_size = block_size.checked_shl(cluster_bits as u32).unwrap_or(0);
                        let count = node.data_size.unwrap_or(0).div_ceil(cluster_size.max(1));
                        let mut mapped_heads = 0usize;
                        for index in 0..count.min(1_000_000) {
                            let object = ObjectRef::CompressionIndex { inode: nid, index };
                            let index_fields = locate_fields(bytes, mode, object);
                            if index_fields.is_empty() {
                                break;
                            }
                            node.related.push(RelatedObject {
                                label: format!("lcluster [{index}]"),
                                object,
                            });
                            let kind =
                                decoded_field(&index_fields, "erofs.compression.index.advise")
                                    .unwrap_or(2)
                                    & 3;
                            if advise & 0x28 == 0
                                && kind != 2
                                && let Some(block) =
                                    decoded_field(&index_fields, "erofs.compression.index.blkaddr")
                            {
                                let next_fields = locate_fields(
                                    bytes,
                                    mode,
                                    ObjectRef::CompressionIndex {
                                        inode: nid,
                                        index: index + 1,
                                    },
                                );
                                let next_advise =
                                    decoded_field(&next_fields, "erofs.compression.index.advise")
                                        .unwrap_or(0);
                                let blocks = if next_advise & 3 == 2 && next_advise & (1 << 11) != 0
                                {
                                    decoded_field(
                                        &next_fields,
                                        "erofs.compression.index.clusterofs",
                                    )
                                    .unwrap_or(1)
                                    .max(1)
                                } else {
                                    1
                                };
                                if let Ok(span) = Span::new(
                                    block.saturating_mul(block_size),
                                    blocks.saturating_mul(block_size),
                                ) {
                                    node.extents.push(PhysicalExtent {
                                        role: ExtentRole::Data,
                                        span,
                                        logical_offset: Some(index * cluster_size),
                                    });
                                    mapped_heads += 1;
                                }
                            }
                        }
                        if advise & 0x20 != 0 {
                            node.placement_note = Some(
                                "fragment-backed compressed payload is stored in the packed inode"
                                    .to_string(),
                            );
                        } else if advise & 0x08 != 0 {
                            node.placement_note = Some(
                                "inline compressed pcluster mapping is not exposed".to_string(),
                            );
                        } else if mapped_heads > 0 {
                            node.placement_note = None;
                        }
                    } else {
                        add_related(
                            node,
                            bytes,
                            mode,
                            "compact lcluster pack [0]".to_string(),
                            ObjectRef::CompressionCompactPack {
                                inode: nid,
                                index: 0,
                            },
                        );
                    }
                }
                _ => {}
            }
        }
    }

    fn rebuild_block_owners(&mut self) {
        self.block_owners = vec![Vec::new(); self.block_kinds.len()];
        for (node_index, node) in self.nodes.iter().enumerate() {
            for extent in &node.extents {
                mark_blocks(
                    &mut self.block_kinds,
                    extent.span,
                    self.block_size,
                    match extent.role {
                        ExtentRole::Superblock => BlockKind::Superblock,
                        ExtentRole::Inode | ExtentRole::Xattr => BlockKind::Metadata,
                        ExtentRole::Data | ExtentRole::InlineData if node.is_dir => {
                            BlockKind::DirData
                        }
                        ExtentRole::Data | ExtentRole::InlineData => BlockKind::FileData,
                    },
                );
                if extent.span.len == 0 {
                    continue;
                }
                let first = extent.span.offset / self.block_size;
                let last = extent.span.offset.saturating_add(extent.span.len - 1) / self.block_size;
                for block in first..=last {
                    if let Some(owners) = self.block_owners.get_mut(block as usize)
                        && !owners.contains(&node_index)
                    {
                        owners.push(node_index);
                    }
                }
            }
        }
    }
}

fn locate_fields(bytes: &[u8], mode: ParseMode, object: ObjectRef) -> Vec<FieldRow> {
    let reader = SliceReader::new(bytes);
    let Ok(locator) = Locator::with_mode(&reader, mode) else {
        return Vec::new();
    };
    FIELDS
        .iter()
        .filter_map(|field| {
            locator
                .locate(object, field)
                .ok()
                .map(|occurrence| FieldRow {
                    id: field.id,
                    span: occurrence.span,
                    raw_hex: hex(&occurrence.raw[..usize::from(occurrence.raw_len)]),
                    decoded: occurrence.value,
                })
        })
        .collect()
}

fn decoded_field(fields: &[FieldRow], id: &str) -> Option<u64> {
    fields.iter().find_map(|field| {
        (field.id == id).then_some(match field.decoded {
            DecodedValue::Unsigned(value) => Some(value),
            DecodedValue::Bytes { .. } => None,
        })?
    })
}

fn add_related(
    node: &mut Node,
    bytes: &[u8],
    mode: ParseMode,
    label: String,
    object: ObjectRef,
) -> bool {
    if locate_fields(bytes, mode, object).is_empty() {
        false
    } else {
        node.related.push(RelatedObject { label, object });
        true
    }
}

fn parse_number(value: &str) -> std::result::Result<u64, std::num::ParseIntError> {
    let value = value.trim();
    value
        .strip_prefix("0x")
        .map_or_else(|| value.parse(), |hex| u64::from_str_radix(hex, 16))
}

/// Marks every block touched by `span` as `kind`; stronger kinds
/// (superblock > metadata > dir data > file data) are never overwritten.
fn mark_blocks(kinds: &mut [BlockKind], span: Span, block_size: u64, kind: BlockKind) {
    const fn priority(kind: BlockKind) -> u8 {
        match kind {
            BlockKind::Unused => 0,
            BlockKind::FileData => 1,
            BlockKind::DirData => 2,
            BlockKind::Metadata => 3,
            BlockKind::Superblock => 4,
        }
    }
    if span.len == 0 {
        return;
    }
    let first = span.offset / block_size;
    let last = (span.offset + span.len - 1) / block_size;
    for block in first..=last {
        if let Some(slot) = kinds.get_mut(block as usize)
            && priority(kind) > priority(*slot)
        {
            *slot = kind;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Focus {
    Tree,
    Fields,
    Hex,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValueFormat {
    Auto,
    Decimal,
    Hexadecimal,
    Binary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InputMode {
    Search,
    Jump,
}

impl ValueFormat {
    fn next(self) -> Self {
        match self {
            Self::Auto => Self::Decimal,
            Self::Decimal => Self::Hexadecimal,
            Self::Hexadecimal => Self::Binary,
            Self::Binary => Self::Auto,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Decimal => "dec",
            Self::Hexadecimal => "hex",
            Self::Binary => "bin",
        }
    }
}

struct ViewState {
    model: ImageModel,
    mode: ParseMode,
    fields: Vec<FieldRow>,
    tree_sel: usize,
    field_sel: usize,
    focus: Focus,
    zoom_selected: bool,
    collapsed: HashSet<usize>,
    value_format: ValueFormat,
    related_sel: usize,
    extent_sel: usize,
    hex_scroll_rows: u64,
    hex_override: Option<Span>,
    input_mode: Option<InputMode>,
    input: String,
    status: Option<String>,
}

impl ViewState {
    fn new(model: ImageModel, mode: ParseMode) -> Self {
        let mut state = Self {
            fields: Vec::new(),
            model,
            mode,
            tree_sel: 0,
            field_sel: 0,
            focus: Focus::Tree,
            zoom_selected: false,
            collapsed: HashSet::new(),
            value_format: ValueFormat::Auto,
            related_sel: 0,
            extent_sel: 0,
            hex_scroll_rows: 0,
            hex_override: None,
            input_mode: None,
            input: String::new(),
            status: None,
        };
        state.reload_fields();
        state
    }

    fn reload_fields(&mut self) {
        let node = &self.model.nodes[self.tree_sel];
        self.related_sel = self.related_sel.min(node.related.len());
        let object = if self.related_sel == 0 {
            node.object
        } else {
            node.related[self.related_sel - 1].object
        };
        self.fields = self.model.fields(object, self.mode);
        self.field_sel = 0;
        self.hex_scroll_rows = 0;
        self.hex_override = None;
    }

    fn select_node(&mut self, index: usize) {
        self.tree_sel = index;
        self.related_sel = 0;
        self.extent_sel = 0;
        self.reload_fields();
    }

    fn move_selection(&mut self, delta: i64, page: bool) {
        match self.focus {
            Focus::Tree => {
                let visible = self.visible_node_indices();
                if visible.is_empty() {
                    return;
                }
                let current = visible
                    .iter()
                    .position(|index| *index == self.tree_sel)
                    .unwrap_or(0);
                let step = if page { delta * 10 } else { delta };
                let next = (current as i64 + step).clamp(0, visible.len() as i64 - 1) as usize;
                self.select_node(visible[next]);
            }
            Focus::Fields => {
                if self.fields.is_empty() {
                    return;
                }
                let step = if page { delta * 10 } else { delta };
                self.field_sel =
                    (self.field_sel as i64 + step).clamp(0, self.fields.len() as i64 - 1) as usize;
            }
            Focus::Hex => {
                let step = if page { delta * 8 } else { delta };
                self.hex_scroll_rows = (self.hex_scroll_rows as i64 + step).max(0) as u64;
            }
        }
    }

    fn visible_node_indices(&self) -> Vec<usize> {
        let mut visible = Vec::with_capacity(self.model.nodes.len());
        let mut hidden_below = None;
        for (index, node) in self.model.nodes.iter().enumerate() {
            if let Some(depth) = hidden_below {
                if node.depth > depth {
                    continue;
                }
                hidden_below = None;
            }
            visible.push(index);
            if self.collapsed.contains(&index) {
                hidden_below = Some(node.depth);
            }
        }
        visible
    }

    fn has_children(&self, index: usize) -> bool {
        self.model
            .nodes
            .get(index + 1)
            .is_some_and(|next| next.depth > self.model.nodes[index].depth)
    }

    fn toggle_directory(&mut self) {
        if self.model.nodes[self.tree_sel].kind != ObjectKind::Directory
            || !self.has_children(self.tree_sel)
        {
            return;
        }
        if !self.collapsed.insert(self.tree_sel) {
            self.collapsed.remove(&self.tree_sel);
        }
    }

    fn tree_right(&mut self) {
        if self.collapsed.remove(&self.tree_sel) {
            return;
        }
        if self.has_children(self.tree_sel) {
            self.select_node(self.tree_sel + 1);
        }
    }

    fn tree_left(&mut self) {
        if self.model.nodes[self.tree_sel].kind == ObjectKind::Directory
            && self.has_children(self.tree_sel)
            && !self.collapsed.contains(&self.tree_sel)
        {
            self.collapsed.insert(self.tree_sel);
            return;
        }
        let depth = self.model.nodes[self.tree_sel].depth;
        if depth == 0 {
            return;
        }
        if let Some(parent) = (0..self.tree_sel)
            .rev()
            .find(|index| self.model.nodes[*index].depth + 1 == depth)
        {
            self.select_node(parent);
        }
    }

    fn cycle_related(&mut self) {
        let count = self.selected_node().related.len() + 1;
        self.related_sel = (self.related_sel + 1) % count;
        self.reload_fields();
    }

    fn selected_object_label(&self) -> &str {
        let node = self.selected_node();
        if self.related_sel == 0 {
            if node.kind == ObjectKind::Superblock {
                "superblock"
            } else {
                "inode"
            }
        } else {
            &node.related[self.related_sel - 1].label
        }
    }

    fn data_extents(&self) -> Vec<&PhysicalExtent> {
        self.selected_node()
            .extents
            .iter()
            .filter(|extent| matches!(extent.role, ExtentRole::Data | ExtentRole::InlineData))
            .collect()
    }

    fn cycle_extent(&mut self, delta: i64) {
        let count = self.data_extents().len();
        if count == 0 {
            return;
        }
        self.extent_sel = (self.extent_sel as i64 + delta).rem_euclid(count as i64) as usize;
        self.hex_scroll_rows = 0;
        self.hex_override = None;
    }

    /// The span shown in the hex pane: the selected field when the fields
    /// pane is focused, otherwise the selected object.
    fn active_span(&self) -> Span {
        if let Some(span) = self.hex_override {
            return span;
        }
        if self.focus == Focus::Fields
            && let Some(field) = self.fields.get(self.field_sel)
        {
            return field.span;
        }
        if self.related_sel > 0
            && let (Some(first), Some(last)) = (
                self.fields.iter().map(|field| field.span.offset).min(),
                self.fields
                    .iter()
                    .map(|field| field.span.offset.saturating_add(field.span.len))
                    .max(),
            )
            && let Ok(span) = Span::new(first, last.saturating_sub(first))
        {
            return span;
        }
        let node = self.selected_node();
        if matches!(node.kind, ObjectKind::File | ObjectKind::Symlink)
            && let Some(extent) = self.data_extents().get(self.extent_sel)
        {
            return extent.span;
        }
        node.span
    }

    fn active_span_label(&self) -> &'static str {
        if self.hex_override.is_some() {
            return "jump target";
        }
        if self.focus == Focus::Fields {
            return "field";
        }
        if self.related_sel > 0 {
            return "structure bytes";
        }
        let node = self.selected_node();
        if matches!(node.kind, ObjectKind::File | ObjectKind::Symlink)
            && node
                .extents
                .iter()
                .any(|extent| matches!(extent.role, ExtentRole::Data | ExtentRole::InlineData))
        {
            "file data"
        } else if matches!(node.kind, ObjectKind::File | ObjectKind::Symlink)
            && node.data_size == Some(0)
        {
            "empty file · inode"
        } else {
            "object bytes"
        }
    }

    fn selected_node(&self) -> &Node {
        &self.model.nodes[self.tree_sel]
    }

    fn begin_input(&mut self, mode: InputMode) {
        self.input_mode = Some(mode);
        self.input.clear();
        self.status = None;
    }

    fn apply_input(&mut self) {
        let Some(mode) = self.input_mode.take() else {
            return;
        };
        let query = self.input.trim().to_string();
        self.input.clear();
        if query.is_empty() {
            return;
        }
        match mode {
            InputMode::Search => {
                let needle = query.to_lowercase();
                let start = self.tree_sel.saturating_add(1);
                let found = (start..self.model.nodes.len())
                    .chain(0..start.min(self.model.nodes.len()))
                    .find(|index| {
                        self.model.nodes[*index]
                            .label
                            .to_lowercase()
                            .contains(&needle)
                    });
                if let Some(index) = found {
                    self.collapsed.clear();
                    self.select_node(index);
                    self.focus = Focus::Tree;
                } else {
                    self.status = Some(format!("no path matching {query:?}"));
                }
            }
            InputMode::Jump => self.apply_jump(&query),
        }
    }

    fn apply_jump(&mut self, query: &str) {
        if let Some(value) = query.strip_prefix("nid:") {
            let Ok(nid) = parse_number(value) else {
                self.status = Some("invalid nid".to_string());
                return;
            };
            if let Some(index) = self.model.nodes.iter().position(
                |node| matches!(node.object, ObjectRef::Inode { nid: value, .. } if value == nid),
            ) {
                self.collapsed.clear();
                self.select_node(index);
                self.focus = Focus::Tree;
            } else {
                self.status = Some(format!("nid {nid} not found"));
            }
            return;
        }
        let (offset, block_jump) = if let Some(value) = query
            .strip_prefix("block:")
            .or_else(|| query.strip_prefix("b:"))
        {
            let Ok(block) = parse_number(value) else {
                self.status = Some("invalid block".to_string());
                return;
            };
            (block.saturating_mul(self.model.block_size), true)
        } else {
            let Ok(offset) = parse_number(query.strip_prefix("offset:").unwrap_or(query)) else {
                self.status = Some("use offset, block:N, or nid:N".to_string());
                return;
            };
            (offset, false)
        };
        if offset >= self.model.bytes.len() as u64 {
            self.status = Some(format!("offset {offset:#x} is outside the image"));
            return;
        }
        let block = (offset / self.model.block_size) as usize;
        if let Some(owner) = self
            .model
            .block_owners
            .get(block)
            .and_then(|owners| owners.first())
        {
            self.collapsed.clear();
            self.select_node(*owner);
        }
        let len = if block_jump {
            self.model.block_size
        } else {
            256
        }
        .min(self.model.bytes.len() as u64 - offset);
        self.hex_override = Span::new(offset, len).ok();
        self.hex_scroll_rows = 0;
        self.focus = Focus::Hex;
    }

    /// Inclusive-exclusive block range displayed by the physical map.
    fn visible_blocks(&self) -> (usize, usize) {
        let total = self.model.block_kinds.len();
        if !self.zoom_selected || total == 0 {
            return (0, total);
        }
        let block_size = self.model.block_size;
        let node = self.selected_node();
        let first = node
            .extents
            .iter()
            .filter(|extent| extent.span.len > 0)
            .map(|extent| (extent.span.offset / block_size) as usize)
            .min()
            .unwrap_or(0);
        let end = node
            .extents
            .iter()
            .filter(|extent| extent.span.len > 0)
            .map(|extent| {
                (extent
                    .span
                    .offset
                    .saturating_add(extent.span.len)
                    .div_ceil(block_size)) as usize
            })
            .max()
            .unwrap_or(total);
        (first.saturating_sub(2), end.saturating_add(2).min(total))
    }
}

pub fn view(args: ViewArgs) -> Result<()> {
    let bytes = fs::read(&args.image).with_context(|| format!("failed to read {}", args.image))?;
    let mode = match args.mode {
        ViewMode::Strict => ParseMode::Strict,
        ViewMode::Tolerant => ParseMode::Tolerant,
    };
    let model = ImageModel::build(bytes, mode)?;
    if args.no_tui || !io::stdout().is_terminal() {
        print_plain(&model, mode);
        return Ok(());
    }
    run_tui(model, mode, &args.image)
}

/// Plain-text rendering for non-interactive use and tests.
fn print_plain(model: &ImageModel, mode: ParseMode) {
    let image_len = model.bytes.len() as u64;
    println!(
        "image: {} bytes, {} blocks of {} bytes",
        image_len,
        model.block_kinds.len(),
        model.block_size
    );
    let mut counts = [0u64; 5];
    for kind in &model.block_kinds {
        counts[*kind as usize] += 1;
    }
    for kind in [
        BlockKind::Superblock,
        BlockKind::Metadata,
        BlockKind::DirData,
        BlockKind::FileData,
        BlockKind::Unused,
    ] {
        println!("  {:<10} {} blocks", kind.label(), counts[kind as usize]);
    }
    if let Some(warning) = &model.walk_warning {
        println!("warning: {warning}");
    }
    for node in &model.nodes {
        let indent = "  ".repeat(node.depth);
        println!(
            "{}{}  [{}] @{}+{}",
            indent, node.label, node.detail, node.span.offset, node.span.len
        );
        for extent in &node.extents {
            let logical = extent
                .logical_offset
                .map_or_else(|| "".to_string(), |offset| format!(" logical@{offset}"));
            println!(
                "{}    extent {:<11} physical@{}+{}{}",
                indent,
                extent.role.label(),
                extent.span.offset,
                extent.span.len,
                logical
            );
        }
        if let Some(note) = &node.placement_note {
            println!("{}    extent unavailable: {note}", indent);
        }
        for field in model.fields(node.object, mode) {
            println!(
                "{}    {:<44} @{:>8}+{:<3} {:<20} {}",
                indent,
                field.id,
                field.span.offset,
                field.span.len,
                field.raw_hex,
                display_value(field.decoded)
            );
        }
        for related in &node.related {
            println!("{}    object {}", indent, related.label);
            for field in model.fields(related.object, mode) {
                println!(
                    "{}      {:<42} @{:>8}+{:<3} {:<20} {}",
                    indent,
                    field.id,
                    field.span.offset,
                    field.span.len,
                    field.raw_hex,
                    display_value(field.decoded)
                );
            }
        }
    }
}

fn run_tui(model: ImageModel, mode: ParseMode, image_path: &str) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    if let Err(error) = execute!(stdout, EnterAlternateScreen, cursor::Hide) {
        let _ = disable_raw_mode();
        return Err(error.into());
    }
    let result = Terminal::new(CrosstermBackend::new(stdout))
        .map_err(anyhow::Error::from)
        .and_then(|mut terminal| event_loop(&mut terminal, model, mode, image_path));
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, cursor::Show);
    result
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    model: ImageModel,
    mode: ParseMode,
    image_path: &str,
) -> Result<()> {
    let mut state = ViewState::new(model, mode);
    loop {
        terminal.draw(|frame| render(frame, &state, image_path))?;
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if state.input_mode.is_some() {
            match key.code {
                KeyCode::Esc => {
                    state.input_mode = None;
                    state.input.clear();
                }
                KeyCode::Enter => state.apply_input(),
                KeyCode::Backspace => {
                    state.input.pop();
                }
                KeyCode::Char(character) => state.input.push(character),
                _ => {}
            }
            continue;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
            KeyCode::Char('z') => state.zoom_selected = !state.zoom_selected,
            KeyCode::Char('v') => state.value_format = state.value_format.next(),
            KeyCode::Char('a') => state.value_format = ValueFormat::Auto,
            KeyCode::Char('d') => state.value_format = ValueFormat::Decimal,
            KeyCode::Char('x') => state.value_format = ValueFormat::Hexadecimal,
            KeyCode::Char('b') => state.value_format = ValueFormat::Binary,
            KeyCode::Char('/') => state.begin_input(InputMode::Search),
            KeyCode::Char('g') => state.begin_input(InputMode::Jump),
            KeyCode::Char('o') => state.cycle_related(),
            KeyCode::Char('[') => state.cycle_extent(-1),
            KeyCode::Char(']') => state.cycle_extent(1),
            KeyCode::Tab => {
                state.focus = match state.focus {
                    Focus::Tree => Focus::Fields,
                    Focus::Fields => Focus::Hex,
                    Focus::Hex => Focus::Tree,
                };
            }
            KeyCode::Left if state.focus == Focus::Tree => state.tree_left(),
            KeyCode::Right if state.focus == Focus::Tree => state.tree_right(),
            KeyCode::Enter | KeyCode::Char(' ') if state.focus == Focus::Tree => {
                state.toggle_directory();
            }
            KeyCode::Up | KeyCode::Char('k') => state.move_selection(-1, false),
            KeyCode::Down | KeyCode::Char('j') => state.move_selection(1, false),
            KeyCode::PageUp => state.move_selection(-1, true),
            KeyCode::PageDown => state.move_selection(1, true),
            KeyCode::Home => match state.focus {
                Focus::Tree => {
                    let first = state.visible_node_indices().first().copied().unwrap_or(0);
                    state.select_node(first);
                }
                Focus::Fields => state.field_sel = 0,
                Focus::Hex => state.hex_scroll_rows = 0,
            },
            KeyCode::End => {
                let last = match state.focus {
                    Focus::Tree => state.visible_node_indices().last().copied().unwrap_or(0),
                    Focus::Fields => state.fields.len().saturating_sub(1),
                    Focus::Hex => {
                        state.hex_scroll_rows = u64::MAX;
                        0
                    }
                };
                match state.focus {
                    Focus::Tree => state.select_node(last),
                    Focus::Fields => state.field_sel = last,
                    Focus::Hex => {}
                }
            }
            _ => {}
        }
    }
}

fn render(frame: &mut Frame, state: &ViewState, image_path: &str) {
    // Explicitly erase the previous frame. Some terminals otherwise retain
    // cells in blank rows when panes move or the window is resized.
    frame.render_widget(Clear, frame.area());
    frame.render_widget(
        Block::default().style(Style::default().fg(TEXT).bg(BG)),
        frame.area(),
    );
    let areas = Split::vertical([
        Constraint::Length(2),
        Constraint::Length(6),
        Constraint::Min(8),
        Constraint::Length(7),
        Constraint::Length(8),
        Constraint::Length(1),
    ])
    .split(frame.area());

    render_header(frame, areas[0], state, image_path);
    render_map(frame, areas[1], state);
    let panes =
        Split::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)]).split(areas[2]);
    render_tree(frame, panes[0], state);
    render_fields(frame, panes[1], state);
    render_extents(frame, areas[3], state);
    render_hex(frame, areas[4], state);
    let help = match (state.input_mode, state.status.as_ref()) {
        (Some(mode), _) => format!(
            "{}{}",
            if mode == InputMode::Search {
                "/"
            } else {
                "jump> "
            },
            state.input
        ),
        (None, Some(status)) => format!("⚠ {status} · / search · g jump · q quit"),
        (None, None) => format!(
            "↑/↓ navigate · tab pane · / search · g jump · [/] extent · o object · v values:{} · q quit",
            state.value_format.label()
        ),
    };
    frame.render_widget(
        Paragraph::new(help).style(Style::default().fg(MUTED).bg(BG)),
        areas[5],
    );
}

fn render_header(frame: &mut Frame, area: Rect, state: &ViewState, image_path: &str) {
    let model = &state.model;
    let name = Path::new(image_path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| image_path.to_string());
    let mut spans = vec![
        Text::styled(
            format!(" {name} "),
            Style::default()
                .fg(TEXT)
                .bg(SELECTED_BG)
                .add_modifier(Modifier::BOLD),
        ),
        Text::styled(
            format!(
                "  {} · {} blocks · {} per block",
                format_bytes(model.bytes.len() as u64),
                model.block_kinds.len(),
                format_bytes(model.block_size)
            ),
            Style::default().fg(MUTED),
        ),
    ];
    if let Some(warning) = &model.walk_warning {
        spans.push(Text::styled(
            format!("  ⚠ {warning}"),
            Style::default().fg(ACCENT),
        ));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(BG)),
        area,
    );
}

fn render_map(frame: &mut Frame, area: Rect, state: &ViewState) {
    let model = &state.model;
    let node = state.selected_node();
    let (visible_start, visible_end) = state.visible_blocks();
    let visible_count = visible_end.saturating_sub(visible_start);
    let inner_width = usize::from(area.width.saturating_sub(2));
    let inner_height = usize::from(area.height.saturating_sub(2));
    if inner_width < 12 || inner_height == 0 || visible_count == 0 {
        return;
    }
    let label_width = 9usize;
    let available_width = inner_width - label_width;
    // Small images should look like blocks rather than a handful of pixels.
    // Grow each cell up to four terminal columns while keeping large images
    // dense and allowing them to wrap over the available rows.
    let cell_width = (available_width / visible_count).clamp(1, 4);
    let columns = (available_width / cell_width).max(1);
    let grid_rows = (inner_height.saturating_sub(1) / 2).max(1);
    let cells = columns * grid_rows;
    let shown_cells = cells.min(visible_count);
    let mut lines = Vec::with_capacity(inner_height);

    for row in 0..grid_rows {
        let first_cell = row * columns;
        if first_cell >= shown_cells {
            break;
        }
        let row_block = visible_start + first_cell * visible_count / shown_cells;
        let mut top = vec![Text::styled(
            format!("blk {row_block:>4} "),
            Style::default().fg(MUTED),
        )];
        let mut bottom = vec![Text::styled(
            format!("{:#07x} ", row_block as u64 * model.block_size),
            Style::default().fg(MUTED),
        )];
        for cell in first_cell..(first_cell + columns).min(shown_cells) {
            let start = visible_start + cell * visible_count / shown_cells;
            let end = (visible_start + (cell + 1) * visible_count / shown_cells)
                .max(start + 1)
                .min(visible_end);
            let kind = strongest_kind(&model.block_kinds[start..end]);
            let selected = node.extents.iter().any(|extent| {
                extent.span.len > 0 && blocks_overlap(extent.span, model.block_size, start, end)
            });
            let mixed = (start..end).any(|block| {
                model
                    .block_owners
                    .get(block)
                    .is_some_and(|owners| owners.len() > 1)
            });
            let style = if selected {
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(kind.color())
            };
            let painted_width = cell_width.saturating_sub(1).max(1);
            let symbol = if selected {
                "◆"
            } else if mixed {
                "▒"
            } else {
                "█"
            }
            .repeat(painted_width);
            top.push(Text::styled(symbol.clone(), style));
            bottom.push(Text::styled(symbol, style));
            if cell_width > 1 {
                top.push(Text::raw(" "));
                bottom.push(Text::raw(" "));
            }
        }
        lines.push(Line::from(top));
        lines.push(Line::from(bottom));
    }
    lines.push(Line::from(vec![
        Text::styled("◆ selected  ", Style::default().fg(ACCENT)),
        Text::styled("▒ shared  ", Style::default().fg(MUTED)),
        Text::styled("█ super  ", Style::default().fg(Color::Magenta)),
        Text::styled("█ metadata  ", Style::default().fg(Color::Cyan)),
        Text::styled("█ directory  ", Style::default().fg(Color::Green)),
        Text::styled("█ file  ", Style::default().fg(Color::Blue)),
        Text::styled("█ unused", Style::default().fg(MUTED)),
    ]));
    let zoom = if state.zoom_selected {
        "selected"
    } else {
        "whole image"
    };
    let title = format!(
        "physical layout · {zoom} · blocks {visible_start}..{visible_end} / {} · {}",
        model.block_kinds.len(),
        node.label
    );
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().bg(SURFACE))
            .block(section_block(title)),
        area,
    );
}

fn strongest_kind(kinds: &[BlockKind]) -> BlockKind {
    kinds
        .iter()
        .copied()
        .max_by_key(|kind| match kind {
            BlockKind::Superblock => 4,
            BlockKind::Metadata => 3,
            BlockKind::DirData => 2,
            BlockKind::FileData => 1,
            BlockKind::Unused => 0,
        })
        .unwrap_or(BlockKind::Unused)
}

fn object_display_name(node: &Node) -> String {
    if node.label == "/" || node.kind == ObjectKind::Superblock {
        return node.label.clone();
    }
    Path::new(&node.label)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| node.label.clone())
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn blocks_overlap(span: Span, block_size: u64, start: usize, end: usize) -> bool {
    let extent_start = span.offset / block_size;
    let extent_end = span.offset.saturating_add(span.len).div_ceil(block_size);
    extent_start < end as u64 && extent_end > start as u64
}

fn render_tree(frame: &mut Frame, area: Rect, state: &ViewState) {
    let focused = state.focus == Focus::Tree;
    let visible = state.visible_node_indices();
    let items: Vec<ListItem> = visible
        .iter()
        .map(|index| {
            let node = &state.model.nodes[*index];
            let name = object_display_name(node);
            let summary = match (node.data_size, node.layout_name) {
                (Some(size), Some(layout)) => format!("  {} · {layout}", format_bytes(size)),
                _ => "  filesystem header".to_string(),
            };
            let icon = if node.kind == ObjectKind::Directory && state.has_children(*index) {
                if state.collapsed.contains(index) {
                    "▸"
                } else {
                    "▾"
                }
            } else {
                node.kind.icon()
            };
            ListItem::new(Line::from(vec![
                Text::styled("│ ".repeat(node.depth), Style::default().fg(BORDER)),
                Text::styled(format!("{icon} "), Style::default().fg(node.kind.color())),
                Text::styled(name, Style::default().fg(TEXT)),
                Text::styled(summary, Style::default().fg(MUTED)),
            ]))
        })
        .collect();
    let mut list_state = ListState::default();
    list_state.select(visible.iter().position(|index| *index == state.tree_sel));
    let list = List::new(items)
        .block(pane_block(
            format!("objects · {}/{}", visible.len(), state.model.nodes.len()),
            focused,
        ))
        .highlight_style(
            Style::default()
                .fg(TEXT)
                .bg(SELECTED_BG)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_stateful_widget(list, area, &mut list_state);
}

fn render_fields(frame: &mut Frame, area: Rect, state: &ViewState) {
    let focused = state.focus == Focus::Fields;
    let prefix = state
        .fields
        .first()
        .and_then(|field| field.id.rsplit_once('.').map(|(prefix, _)| prefix))
        .unwrap_or("fields");
    let rows: Vec<Row> = state
        .fields
        .iter()
        .map(|field| {
            Row::new(vec![
                field.id.rsplit('.').next().unwrap_or(field.id).to_string(),
                format!("{:#x}+{}", field.span.offset, field.span.len),
                field.raw_hex.clone(),
                format_field_value(field, state.value_format),
            ])
            .style(Style::default().fg(TEXT).bg(SURFACE))
        })
        .collect();
    let mut table_state = TableState::default();
    table_state.select((!state.fields.is_empty()).then_some(state.field_sel));
    let table = Table::new(
        rows,
        [
            Constraint::Length(28),
            Constraint::Length(13),
            Constraint::Length(18),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(vec!["FIELD", "PHYSICAL", "RAW BYTES", "DECODED"])
            .style(Style::default().fg(MUTED).bg(SELECTED_BG))
            .bottom_margin(1),
    )
    .block(pane_block(
        format!(
            "{} · {prefix}.* · {} fields · {}",
            state.selected_object_label(),
            state.fields.len(),
            state.value_format.label()
        ),
        focused,
    ))
    .row_highlight_style(
        Style::default()
            .fg(TEXT)
            .bg(SELECTED_BG)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_stateful_widget(table, area, &mut table_state);
}

fn format_field_value(field: &FieldRow, format: ValueFormat) -> String {
    if format != ValueFormat::Auto {
        return format_decoded(field.decoded, format);
    }
    let DecodedValue::Unsigned(value) = field.decoded else {
        if field.id.ends_with(".uuid")
            && let DecodedValue::Bytes { bytes, len: 16 } = field.decoded
        {
            return format!(
                "{}-{}-{}-{}-{}",
                hex(&bytes[0..4]),
                hex(&bytes[4..6]),
                hex(&bytes[6..8]),
                hex(&bytes[8..10]),
                hex(&bytes[10..16])
            );
        }
        return format_decoded(field.decoded, format);
    };
    if field.id.ends_with(".magic") {
        return format!("{value:#010x}");
    }
    if field.id.ends_with(".i_mode") {
        return format!("{value:#06o} · {}", unix_mode(value as u16));
    }
    if field.id.ends_with(".i_format") {
        let form = if value & 1 == 0 {
            "compact"
        } else {
            "extended"
        };
        let layout = match (value >> 1) & 7 {
            0 => "plain",
            1 => "compressed-full",
            2 => "inline",
            3 => "compressed-compact",
            4 => "chunked",
            _ => "unknown",
        };
        return format!("{value:#x} · {form}/{layout}");
    }
    if field.id.ends_with(".file_type") {
        let name = match value {
            0 => "unknown",
            1 => "file",
            2 => "directory",
            3 => "char-device",
            4 => "block-device",
            5 => "fifo",
            6 => "socket",
            7 => "symlink",
            _ => "invalid",
        };
        return format!("{value} · {name}");
    }
    if field.id.ends_with("feature_compat") || field.id.ends_with("feature_incompat") {
        return format_feature_flags(field.id.ends_with("feature_compat"), value as u32);
    }
    if (field.id.ends_with(".epoch")
        || field.id.ends_with(".build_time")
        || field.id.ends_with(".i_mtime"))
        && let Ok(seconds) = i64::try_from(value)
        && let Some(time) = chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0)
    {
        return format!("{value} · {}", time.format("%Y-%m-%d %H:%M:%S UTC"));
    }
    format_decoded(field.decoded, format)
}

fn unix_mode(mode: u16) -> String {
    let kind = match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        0o100000 => '-',
        0o060000 => 'b',
        0o020000 => 'c',
        0o010000 => 'p',
        0o140000 => 's',
        _ => '?',
    };
    let mut result = String::from(kind);
    for bit in (0..9).rev() {
        let enabled = mode & (1 << bit) != 0;
        let character = match bit {
            6 if mode & 0o4000 != 0 => {
                if enabled {
                    's'
                } else {
                    'S'
                }
            }
            3 if mode & 0o2000 != 0 => {
                if enabled {
                    's'
                } else {
                    'S'
                }
            }
            0 if mode & 0o1000 != 0 => {
                if enabled {
                    't'
                } else {
                    'T'
                }
            }
            _ if enabled => match bit % 3 {
                2 => 'r',
                1 => 'w',
                _ => 'x',
            },
            _ => '-',
        };
        result.push(character);
    }
    result
}

fn format_feature_flags(compat: bool, value: u32) -> String {
    let definitions: &[(u32, &str)] = if compat {
        &[
            (0x01, "sb-checksum"),
            (0x02, "mtime"),
            (0x04, "xattr-filter"),
            (0x08, "shared-ea-metabox"),
            (0x10, "plain-xattr-prefix"),
            (0x20, "ishare-xattrs"),
        ]
    } else {
        &[
            (0x01, "lz4-0padding"),
            (0x02, "compression-config"),
            (0x04, "chunked-file"),
            (0x08, "device-table"),
            (0x10, "ztailpacking"),
            (0x20, "fragments"),
            (0x40, "xattr-prefixes"),
            (0x80, "48bit"),
            (0x100, "metabox"),
        ]
    };
    let names = definitions
        .iter()
        .filter_map(|(bit, name)| (value & bit != 0).then_some(*name))
        .collect::<Vec<_>>();
    if names.is_empty() {
        format!("{value:#x} · none")
    } else {
        format!("{value:#x} · {}", names.join("|"))
    }
}

fn format_decoded(value: DecodedValue, format: ValueFormat) -> String {
    match value {
        DecodedValue::Unsigned(value) => match format {
            ValueFormat::Auto if value > 9 => format!("{value} · {value:#x}"),
            ValueFormat::Auto | ValueFormat::Decimal => value.to_string(),
            ValueFormat::Hexadecimal => format!("{value:#x}"),
            ValueFormat::Binary => format!("{value:#b}"),
        },
        DecodedValue::Bytes { bytes, len } => {
            let bytes = &bytes[..usize::from(len)];
            match format {
                ValueFormat::Auto => printable_text(bytes)
                    .map(|text| format!("\"{text}\""))
                    .unwrap_or_else(|| format!("0x{}", hex(bytes))),
                ValueFormat::Decimal => bytes
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(" "),
                ValueFormat::Hexadecimal => format!("0x{}", hex(bytes)),
                ValueFormat::Binary => bytes
                    .iter()
                    .map(|byte| format!("{byte:08b}"))
                    .collect::<Vec<_>>()
                    .join(" "),
            }
        }
    }
}

fn printable_text(bytes: &[u8]) -> Option<String> {
    let end = bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    let text = std::str::from_utf8(&bytes[..end]).ok()?;
    if text.is_empty() {
        return None;
    }
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            character if character.is_control() => return None,
            character => escaped.push(character),
        }
    }
    Some(escaped)
}

fn render_extents(frame: &mut Frame, area: Rect, state: &ViewState) {
    let node = state.selected_node();
    let block_size = state.model.block_size;
    let active_block = (state.active_span().offset / block_size) as usize;
    let owners = state
        .model
        .block_owners
        .get(active_block)
        .map(|owners| {
            owners
                .iter()
                .map(|index| state.model.nodes[*index].label.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let mut lines = vec![Line::from(vec![
        Text::styled(
            format!("block {active_block}  "),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Text::styled(
            if owners.is_empty() {
                "no known owner".to_string()
            } else {
                format!("owners: {owners}")
            },
            Style::default().fg(MUTED),
        ),
    ])];
    for extent in &node.extents {
        let first_block = extent.span.offset / block_size;
        let last_block = extent
            .span
            .offset
            .saturating_add(extent.span.len)
            .saturating_sub(1)
            / block_size;
        let logical = extent.logical_offset.map_or_else(
            || "metadata".to_string(),
            |offset| {
                format!(
                    "logical {offset}..{}",
                    offset.saturating_add(extent.span.len)
                )
            },
        );
        lines.push(Line::from(vec![
            Text::styled("■ ", Style::default().fg(extent.role.color(node.is_dir))),
            Text::styled(
                format!("{:<11}", extent.role.label()),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Text::raw(format!(
                " phys {:#x}..{:#x} ({} B) · block {}{} · {}",
                extent.span.offset,
                extent.span.offset.saturating_add(extent.span.len),
                extent.span.len,
                first_block,
                if last_block == first_block {
                    String::new()
                } else {
                    format!("..{last_block}")
                },
                logical,
            )),
        ]));
    }
    if let Some(note) = &node.placement_note {
        lines.push(Line::from(vec![
            Text::styled("⚠ ", Style::default().fg(Color::Yellow)),
            Text::raw(note),
        ]));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().fg(TEXT).bg(SURFACE))
            .block(section_block(format!(
                "selected extents · {} · object {}/{}: {}",
                node.label,
                state.related_sel + 1,
                node.related.len() + 1,
                state.selected_object_label()
            ))),
        area,
    );
}

fn render_hex(frame: &mut Frame, area: Rect, state: &ViewState) {
    let span = state.active_span();
    let bytes = &state.model.bytes;
    let mut title = format!(
        "{} · hex @{:#x}+{}",
        state.active_span_label(),
        span.offset,
        span.len
    );
    if state.active_span_label() == "file data"
        && let Some(preview) = span_text_preview(bytes, span)
    {
        title.push_str(&format!(" · UTF-8 \"{preview}\""));
    }
    let data_extents = state.data_extents();
    if state.active_span_label() == "file data" && data_extents.len() > 1 {
        title.push_str(&format!(
            " · extent {}/{}",
            state.extent_sel + 1,
            data_extents.len()
        ));
    }

    // Show the rows covering the span, with one row of context before.
    let row = |offset: u64| offset / 16;
    let context_row = row(span.offset).saturating_sub(1);
    let last_row = row(span.offset.saturating_add(span.len).saturating_sub(1));
    let max_rows = usize::from(area.height.saturating_sub(2));
    let total_rows = last_row.saturating_sub(context_row).saturating_add(1);
    let max_scroll = total_rows.saturating_sub(max_rows as u64);
    let first_row = context_row + state.hex_scroll_rows.min(max_scroll);
    let mut lines = Vec::new();
    for r in first_row..=last_row.min(first_row + max_rows.saturating_sub(1) as u64) {
        let base = r * 16;
        let mut spans = vec![Text::styled(
            format!("{base:08x}  "),
            Style::default().fg(Color::Gray),
        )];
        let mut ascii = String::new();
        for i in 0..16u64 {
            let at = base + i;
            let byte = bytes.get(at as usize).copied();
            let in_span = at >= span.offset && at < span.offset + span.len;
            let text = byte.map_or_else(|| "··".to_string(), |b| format!("{b:02x}"));
            spans.push(Text::styled(
                text,
                if in_span {
                    Style::default().fg(Color::Black).bg(ACCENT)
                } else {
                    Style::default().fg(TEXT)
                },
            ));
            spans.push(Text::raw(if i % 8 == 7 { "  " } else { " " }));
            ascii.push(byte.map_or('·', |b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '·'
                }
            }));
        }
        spans.push(Text::styled(ascii, Style::default().fg(MUTED)));
        lines.push(Line::from(spans));
    }
    if lines.is_empty() {
        lines.push(Line::from("span outside image"));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().fg(TEXT).bg(SURFACE))
            .block(pane_block(title, state.focus == Focus::Hex)),
        area,
    );
}

fn span_text_preview(bytes: &[u8], span: Span) -> Option<String> {
    let start = usize::try_from(span.offset).ok()?;
    let len = usize::try_from(span.len.min(4096)).ok()?;
    let end = start.checked_add(len)?.min(bytes.len());
    let text = printable_text(bytes.get(start..end)?)?;
    let mut preview: String = text.chars().take(40).collect();
    if text.chars().count() > 40 {
        preview.push('…');
    }
    Some(preview)
}

fn section_block(title: String) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(Text::styled(
            format!(" {title} "),
            Style::default().fg(MUTED).add_modifier(Modifier::BOLD),
        ))
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().fg(TEXT).bg(SURFACE))
}

fn pane_block(title: String, focused: bool) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(Text::styled(
            format!(" {title}{} ", if focused { " · active" } else { "" }),
            Style::default()
                .fg(if focused { ACCENT } else { MUTED })
                .add_modifier(Modifier::BOLD),
        ))
        .border_style(if focused {
            Style::default().fg(ACCENT)
        } else {
            Style::default().fg(BORDER)
        })
        .style(Style::default().fg(TEXT).bg(SURFACE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use std::sync::atomic::{AtomicU32, Ordering};

    static TEMP_COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Builds a small image with the crate's own builder.
    fn fixture_image() -> Vec<u8> {
        let dir = std::env::temp_dir().join(format!(
            "erofs-view-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::write(dir.join("etc").join("issue"), b"test issue\n").unwrap();
        fs::write(dir.join("big.bin"), vec![7u8; 9000]).unwrap();
        std::os::unix::fs::symlink("etc/issue", dir.join("link")).unwrap();
        let image = erofs_rs::builder::ImageBuilder::new()
            .fixed_time(1_700_000_000)
            .build_from_dir(&dir)
            .unwrap();
        let _ = fs::remove_dir_all(&dir);
        image
    }

    #[test]
    fn model_covers_superblock_tree_and_block_kinds() {
        let model = ImageModel::build(fixture_image(), ParseMode::Strict).unwrap();
        assert_eq!(model.block_size, 4096);
        assert!(model.walk_warning.is_none());
        // superblock + root + etc + issue + big.bin + link
        assert_eq!(model.nodes.len(), 6);
        assert_eq!(model.nodes[0].label, "superblock");
        assert_eq!(model.nodes[1].label, "/");
        let labels: Vec<_> = model.nodes.iter().map(|n| n.label.as_str()).collect();
        assert!(labels.contains(&"/etc"));
        assert!(labels.contains(&"/etc/issue"));
        assert!(labels.contains(&"/big.bin"));
        assert!(labels.contains(&"/link"));

        let big = model
            .nodes
            .iter()
            .find(|node| node.label == "/big.bin")
            .unwrap();
        assert_eq!(big.extents.len(), 2);
        assert_eq!(big.extents[0].role, ExtentRole::Inode);
        assert_eq!(big.extents[1].role, ExtentRole::Data);
        assert_eq!(big.extents[1].span.len, 9000);
        assert_eq!(big.extents[1].logical_offset, Some(0));

        let root = model.nodes.iter().find(|node| node.label == "/").unwrap();
        assert!(root.is_dir);
        assert!(
            root.extents
                .iter()
                .any(|extent| extent.role == ExtentRole::Data)
        );

        // All six inodes fit into block 0 together with the superblock.
        assert_eq!(model.block_kinds[0], BlockKind::Superblock);
        assert!(!model.block_kinds.contains(&BlockKind::Metadata));
        assert!(model.block_kinds.contains(&BlockKind::FileData));
        assert!(model.block_kinds.contains(&BlockKind::DirData));
        // big.bin occupies 3 blocks (9000 bytes).
        let file_blocks = model
            .block_kinds
            .iter()
            .filter(|kind| **kind == BlockKind::FileData)
            .count();
        assert_eq!(file_blocks, 5); // big.bin 3 + issue 1 + link 1
    }

    #[test]
    fn fields_decode_superblock_and_extended_inode() {
        let model = ImageModel::build(fixture_image(), ParseMode::Strict).unwrap();
        let superblock_fields = model.fields(ObjectRef::Superblock, ParseMode::Strict);
        let magic = superblock_fields
            .iter()
            .find(|field| field.id == "erofs.superblock.magic")
            .unwrap();
        assert_eq!(magic.span.offset, erofs_format::SUPERBLOCK_OFFSET);
        assert_eq!(magic.decoded, DecodedValue::Unsigned(0xE0F5_E1E2));

        let root = model.nodes.iter().find(|node| node.label == "/").unwrap();
        let fields = model.fields(root.object, ParseMode::Strict);
        // Builder emits extended inodes; compact fields must mismatch out.
        assert!(
            fields
                .iter()
                .any(|field| field.id == "erofs.inode.extended.i_format")
        );
        assert!(
            !fields
                .iter()
                .any(|field| field.id.starts_with("erofs.inode.compact."))
        );
        let format = fields
            .iter()
            .find(|field| field.id == "erofs.inode.extended.i_format")
            .unwrap();
        assert_eq!(format.decoded, DecodedValue::Unsigned(1));
    }

    #[test]
    fn plain_rendering_lists_objects_and_fields() {
        let model = ImageModel::build(fixture_image(), ParseMode::Strict).unwrap();
        // print_plain writes to stdout; check its building blocks instead via
        // fields(), then exercise the TUI renderer on a test backend below.
        let fields = model.fields(ObjectRef::Superblock, ParseMode::Strict);
        assert!(fields.len() > 20);
    }

    #[test]
    fn tree_collapses_expands_and_navigates_by_parent() {
        let model = ImageModel::build(fixture_image(), ParseMode::Strict).unwrap();
        let mut state = ViewState::new(model, ParseMode::Strict);
        let root = state
            .model
            .nodes
            .iter()
            .position(|node| node.label == "/")
            .unwrap();
        state.tree_sel = root;

        state.toggle_directory();
        assert!(state.collapsed.contains(&root));
        assert_eq!(state.visible_node_indices(), vec![0, root]);

        state.tree_right();
        assert!(!state.collapsed.contains(&root));
        assert_eq!(state.tree_sel, root);

        let etc = state
            .model
            .nodes
            .iter()
            .position(|node| node.label == "/etc")
            .unwrap();
        state.tree_sel = etc;
        state.tree_right();
        assert_eq!(state.model.nodes[state.tree_sel].label, "/etc/issue");
        state.tree_left();
        assert_eq!(state.tree_sel, etc);
        state.tree_left();
        assert!(state.collapsed.contains(&etc));
        assert!(
            !state
                .visible_node_indices()
                .iter()
                .any(|index| state.model.nodes[*index].label == "/etc/issue")
        );
    }

    #[test]
    fn values_support_radices_strings_and_file_data_preview() {
        assert_eq!(
            format_decoded(DecodedValue::Unsigned(42), ValueFormat::Auto),
            "42 · 0x2a"
        );
        assert_eq!(
            format_decoded(DecodedValue::Unsigned(42), ValueFormat::Decimal),
            "42"
        );
        assert_eq!(
            format_decoded(DecodedValue::Unsigned(42), ValueFormat::Hexadecimal),
            "0x2a"
        );
        assert_eq!(
            format_decoded(DecodedValue::Unsigned(42), ValueFormat::Binary),
            "0b101010"
        );
        let mut bytes = [0u8; 64];
        bytes[..10].copy_from_slice(b"hello\n\0\0\0\0");
        assert_eq!(
            format_decoded(DecodedValue::Bytes { bytes, len: 10 }, ValueFormat::Auto),
            "\"hello\\n\""
        );

        let model = ImageModel::build(fixture_image(), ParseMode::Strict).unwrap();
        let mut state = ViewState::new(model, ParseMode::Strict);
        state.tree_sel = state
            .model
            .nodes
            .iter()
            .position(|node| node.label == "/etc/issue")
            .unwrap();
        let span = state.active_span();
        assert_eq!(state.active_span_label(), "file data");
        assert_eq!(
            &state.model.bytes[span.offset as usize..(span.offset + span.len) as usize],
            b"test issue\n"
        );
        assert_eq!(
            span_text_preview(&state.model.bytes, span).as_deref(),
            Some("test issue\\n")
        );

        let mode_field = FieldRow {
            id: "erofs.inode.extended.i_mode",
            span: Span::new(0, 2).unwrap(),
            raw_hex: "ed41".to_string(),
            decoded: DecodedValue::Unsigned(0o040755),
        };
        assert_eq!(
            format_field_value(&mode_field, ValueFormat::Auto),
            "0o40755 · drwxr-xr-x"
        );
    }

    #[test]
    fn related_structures_search_jump_scroll_and_owners_work() {
        let model = ImageModel::build(fixture_image(), ParseMode::Strict).unwrap();
        assert!(model.block_owners[0].len() > 1);
        let mut state = ViewState::new(model, ParseMode::Strict);

        let root = state
            .model
            .nodes
            .iter()
            .position(|node| node.label == "/")
            .unwrap();
        state.select_node(root);
        assert!(
            state
                .selected_node()
                .related
                .iter()
                .any(|object| object.label.starts_with("dirent"))
        );
        state.cycle_related();
        assert!(
            state
                .fields
                .iter()
                .any(|field| field.id == "erofs.dirent.nid")
        );

        state.begin_input(InputMode::Search);
        state.input.push_str("issue");
        state.apply_input();
        assert_eq!(state.selected_node().label, "/etc/issue");

        let data_block = state.data_extents()[0].span.offset / state.model.block_size;
        state.begin_input(InputMode::Jump);
        state.input = format!("block:{data_block}");
        state.apply_input();
        assert_eq!(state.focus, Focus::Hex);
        assert_eq!(
            state.active_span().offset,
            data_block * state.model.block_size
        );

        state.hex_scroll_rows = u64::MAX;
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &state, "image.erofs"))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("owners:"));
        assert!(text.contains("▒ shared"));
    }

    #[test]
    fn tui_renders_tree_fields_and_hex() {
        let model = ImageModel::build(fixture_image(), ParseMode::Strict).unwrap();
        let mut state = ViewState::new(model, ParseMode::Strict);
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &state, "image.erofs"))
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let text: String = buffer.content().iter().map(|cell| cell.symbol()).collect();
        assert!(
            buffer.content().iter().all(|cell| cell.bg != Color::Reset),
            "every cell should have an opaque background"
        );
        assert!(text.contains("superblock"));
        assert!(text.contains("erofs.superblock.*"));
        assert!(text.contains("magic"));
        assert!(text.contains("objects"));
        assert!(text.contains("fields"));
        assert!(text.contains("issue"));
        assert!(text.contains("physical layout"));
        assert!(text.contains("selected extents"));

        // Selecting the magic field highlights its span in the hex pane.
        state.focus = Focus::Fields;
        state.field_sel = state
            .fields
            .iter()
            .position(|field| field.id == "erofs.superblock.magic")
            .unwrap();
        assert_eq!(state.active_span().offset, erofs_format::SUPERBLOCK_OFFSET);
        terminal
            .draw(|frame| render(frame, &state, "image.erofs"))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("hex @0x400+4"));

        // Selecting a file exposes both its inode and its exact data range.
        state.focus = Focus::Tree;
        state.tree_sel = state
            .model
            .nodes
            .iter()
            .position(|node| node.label == "/big.bin")
            .unwrap();
        state.reload_fields();
        state.zoom_selected = true;
        terminal
            .draw(|frame| render(frame, &state, "image.erofs"))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("physical layout · selected"));
        assert!(text.contains("data"));
        assert!(text.contains("9000 B"));
    }

    #[test]
    fn mark_blocks_respects_kind_priority() {
        let span = |offset| Span::new(offset, 1).unwrap();
        let mut kinds = vec![BlockKind::Unused; 4];
        mark_blocks(&mut kinds, span(0), 4096, BlockKind::Superblock);
        mark_blocks(&mut kinds, span(0), 4096, BlockKind::Metadata);
        assert_eq!(kinds[0], BlockKind::Superblock);
        mark_blocks(&mut kinds, span(4096), 4096, BlockKind::Metadata);
        mark_blocks(&mut kinds, span(4096), 4096, BlockKind::FileData);
        assert_eq!(kinds[1], BlockKind::Metadata);
        mark_blocks(&mut kinds, span(8192), 4096, BlockKind::FileData);
        mark_blocks(&mut kinds, span(8192), 4096, BlockKind::DirData);
        assert_eq!(kinds[2], BlockKind::DirData);
        // Zero-length spans mark nothing.
        mark_blocks(
            &mut kinds,
            Span::new(3 * 4096, 0).unwrap(),
            4096,
            BlockKind::Metadata,
        );
        assert_eq!(kinds[3], BlockKind::Unused);
    }

    #[test]
    fn malformed_image_still_renders_superblock() {
        let mut image = fixture_image();
        // Corrupt the root inode's format field: the tree walk fails but the
        // model must still render the superblock.
        let root_format = 36 * 32; // builder nids start at slot 36
        image[root_format as usize] = 0xff;
        image[root_format as usize + 1] = 0xff;
        let model = ImageModel::build(image, ParseMode::Tolerant).unwrap();
        assert!(model.walk_warning.is_some());
        // Only the superblock and the (unwalkable) root inode are listed.
        assert_eq!(model.nodes.len(), 2);
        assert_eq!(model.nodes[0].label, "superblock");
    }
}
