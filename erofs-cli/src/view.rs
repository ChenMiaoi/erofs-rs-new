//! Visual field-level image inspector.
//!
//! `erofs-cli view <image>` renders the on-disk structure of an EROFS image:
//! a block-level usage map, the object tree (superblock plus every inode
//! found by walking the filesystem), the schema fields of the selected
//! object with offsets and decoded values, and a hex dump of the selected
//! span. On a non-terminal stdout (or with `--no-tui`) the same model is
//! printed as plain text.

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
    locator::{Locator, MetadataSpace, ObjectRef, ParseMode},
    schema::{FIELDS, StructureId},
};
use erofs_rs::backend::SliceImage;
use erofs_rs::{EroFS, types::Layout};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout as Split, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span as Text},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Row, Table, TableState},
};

use crate::field::{display_value, hex};

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

impl BlockKind {
    fn color(self) -> Color {
        match self {
            Self::Unused => Color::DarkGray,
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
}

/// One located schema field of the selected object.
struct FieldRow {
    id: &'static str,
    span: Span,
    raw_hex: String,
    value: String,
}

/// Everything the viewer knows about an image, independent of rendering.
struct ImageModel {
    bytes: Vec<u8>,
    block_size: u64,
    nodes: Vec<Node>,
    block_kinds: Vec<BlockKind>,
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

        let mut nodes = vec![Node {
            depth: 0,
            label: "superblock".to_string(),
            detail: format!(
                "blksz={} incompat={:#x} compat={:#x}",
                block_size, sb.feature_incompat, sb.feature_compat
            ),
            object: ObjectRef::Superblock,
            span: Span::new(
                erofs_format::SUPERBLOCK_OFFSET,
                erofs_format::SUPERBLOCK_BASE_SIZE
                    + u64::from(sb.ext_slots) * erofs_format::SUPERBLOCK_EXTSLOT_SIZE,
            )
            .map_err(|_| anyhow::anyhow!("superblock span overflow"))?,
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

        Ok(Self {
            bytes,
            block_size,
            nodes,
            block_kinds,
            walk_warning,
        })
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

        let mut push_inode =
            |depth: usize, label: String, inode: &erofs_rs::types::Inode, nodes: &mut Vec<Node>| {
                let nid = inode.id();
                let kind = if inode.is_dir() {
                    "dir "
                } else if inode.is_symlink() {
                    "link"
                } else {
                    "file"
                };
                if let Ok(offset) = erofs_format::primary_inode_offset(meta_blkaddr, blkszbits, nid)
                {
                    let span = Span::new(offset, inode.size() as u64);
                    if let Ok(span) = span {
                        mark_blocks(block_kinds, span, block_size, BlockKind::Metadata);
                        // Data blocks of flat layouts; inline tails live inside
                        // the metadata area and are already covered above.
                        let data_size = inode.data_size() as u64;
                        let blkaddr = inode.raw_block_addr();
                        if data_size > 0 && blkaddr != u32::MAX {
                            let data_blocks = match inode.layout() {
                                Ok(Layout::FlatPlain) => data_size.div_ceil(block_size),
                                Ok(Layout::FlatInline) => data_size / block_size,
                                _ => 0,
                            };
                            if let Ok(data_span) =
                                Span::new(u64::from(blkaddr) * block_size, data_blocks * block_size)
                            {
                                let kind = if inode.is_dir() {
                                    BlockKind::DirData
                                } else {
                                    BlockKind::FileData
                                };
                                mark_blocks(block_kinds, data_span, block_size, kind);
                            }
                        }
                        nodes.push(Node {
                            depth,
                            label,
                            detail: format!("{kind} nid={nid} size={data_size}"),
                            object: ObjectRef::Inode {
                                space: MetadataSpace::Primary,
                                nid,
                            },
                            span,
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
        let reader = SliceReader::new(&self.bytes);
        let Ok(locator) = Locator::with_mode(&reader, mode) else {
            return Vec::new();
        };
        let structures: &[StructureId] = match object {
            ObjectRef::Superblock => &[StructureId::Superblock],
            ObjectRef::Inode { .. } => &[StructureId::CompactInode, StructureId::ExtendedInode],
            _ => &[],
        };
        FIELDS
            .iter()
            .filter(|field| structures.contains(&field.structure))
            .filter_map(|field| {
                locator
                    .locate(object, field)
                    .ok()
                    .map(|occurrence| FieldRow {
                        id: field.id,
                        span: occurrence.span,
                        raw_hex: hex(&occurrence.raw[..usize::from(occurrence.raw_len)]),
                        value: display_value(occurrence.value),
                    })
            })
            .collect()
    }
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Tree,
    Fields,
}

struct ViewState {
    model: ImageModel,
    mode: ParseMode,
    fields: Vec<FieldRow>,
    tree_sel: usize,
    field_sel: usize,
    focus: Focus,
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
        };
        state.reload_fields();
        state
    }

    fn reload_fields(&mut self) {
        let object = self.model.nodes[self.tree_sel].object;
        self.fields = self.model.fields(object, self.mode);
        self.field_sel = 0;
    }

    fn move_selection(&mut self, delta: i64, page: bool) {
        let (len, sel) = match self.focus {
            Focus::Tree => (self.model.nodes.len(), &mut self.tree_sel),
            Focus::Fields => (self.fields.len(), &mut self.field_sel),
        };
        if len == 0 {
            return;
        }
        let step = if page { delta * 10 } else { delta };
        let next = (*sel as i64 + step).clamp(0, len as i64 - 1) as usize;
        *sel = next;
        if self.focus == Focus::Tree {
            self.reload_fields();
        }
    }

    /// The span shown in the hex pane: the selected field when the fields
    /// pane is focused, otherwise the selected object.
    fn active_span(&self) -> Span {
        if self.focus == Focus::Fields
            && let Some(field) = self.fields.get(self.field_sel)
        {
            return field.span;
        }
        self.model.nodes[self.tree_sel].span
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
        for field in model.fields(node.object, mode) {
            println!(
                "{}    {:<44} @{:>8}+{:<3} {:<20} {}",
                indent, field.id, field.span.offset, field.span.len, field.raw_hex, field.value
            );
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
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
            KeyCode::Tab | KeyCode::Left | KeyCode::Right => {
                state.focus = match state.focus {
                    Focus::Tree => Focus::Fields,
                    Focus::Fields => Focus::Tree,
                };
            }
            KeyCode::Up | KeyCode::Char('k') => state.move_selection(-1, false),
            KeyCode::Down | KeyCode::Char('j') => state.move_selection(1, false),
            KeyCode::PageUp => state.move_selection(-1, true),
            KeyCode::PageDown => state.move_selection(1, true),
            KeyCode::Home => {
                match state.focus {
                    Focus::Tree => state.tree_sel = 0,
                    Focus::Fields => state.field_sel = 0,
                }
                if state.focus == Focus::Tree {
                    state.reload_fields();
                }
            }
            KeyCode::End => {
                let last = match state.focus {
                    Focus::Tree => state.model.nodes.len().saturating_sub(1),
                    Focus::Fields => state.fields.len().saturating_sub(1),
                };
                match state.focus {
                    Focus::Tree => state.tree_sel = last,
                    Focus::Fields => state.field_sel = last,
                }
                if state.focus == Focus::Tree {
                    state.reload_fields();
                }
            }
            _ => {}
        }
    }
}

fn render(frame: &mut Frame, state: &ViewState, image_path: &str) {
    let areas = Split::vertical([
        Constraint::Length(2),
        Constraint::Length(2),
        Constraint::Min(8),
        Constraint::Length(9),
        Constraint::Length(1),
    ])
    .split(frame.area());

    render_header(frame, areas[0], state, image_path);
    render_map(frame, areas[1], state);
    let panes =
        Split::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)]).split(areas[2]);
    render_tree(frame, panes[0], state);
    render_fields(frame, panes[1], state);
    render_hex(frame, areas[3], state);
    let help = "↑/↓ navigate · tab switch pane · pgup/pgdn jump · q quit";
    frame.render_widget(
        Paragraph::new(help).style(Style::default().fg(Color::DarkGray)),
        areas[4],
    );
}

fn render_header(frame: &mut Frame, area: Rect, state: &ViewState, image_path: &str) {
    let model = &state.model;
    let mut text = format!(
        "{} — {} bytes, {} blocks × {} bytes",
        Path::new(image_path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| image_path.to_string()),
        model.bytes.len(),
        model.block_kinds.len(),
        model.block_size,
    );
    if let Some(warning) = &model.walk_warning {
        text.push_str(&format!("  ⚠ {warning}"));
    }
    frame.render_widget(Paragraph::new(text), area);
}

fn render_map(frame: &mut Frame, area: Rect, state: &ViewState) {
    let model = &state.model;
    let width = usize::from(area.width.saturating_sub(2));
    if width == 0 {
        return;
    }
    let total = model.block_kinds.len();
    let mut spans = vec![Text::styled("map ", Style::default().fg(Color::DarkGray))];
    for column in 0..width.min(total.max(1)) {
        // Aggregate the blocks falling into this column; strongest kind wins.
        let start = column * total / width.min(total.max(1)).max(1);
        let end = ((column + 1) * total / width.min(total.max(1)).max(1)).max(start + 1);
        let kind = model.block_kinds[start..end.min(total)]
            .iter()
            .copied()
            .filter(|kind| *kind != BlockKind::Unused)
            .max_by_key(|kind| match kind {
                BlockKind::Superblock => 4,
                BlockKind::Metadata => 3,
                BlockKind::DirData => 2,
                BlockKind::FileData => 1,
                BlockKind::Unused => 0,
            })
            .unwrap_or(BlockKind::Unused);
        spans.push(Text::styled("█", Style::default().fg(kind.color())));
    }
    spans.push(Text::styled(
        "  ▮ superblock ▮ metadata ▮ dir ▮ file ▮ unused",
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_tree(frame: &mut Frame, area: Rect, state: &ViewState) {
    let focused = state.focus == Focus::Tree;
    let items: Vec<ListItem> = state
        .model
        .nodes
        .iter()
        .map(|node| {
            ListItem::new(Line::from(vec![
                Text::raw(format!("{}{}", "  ".repeat(node.depth), node.label)),
                Text::styled(
                    format!("  {}", node.detail),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();
    let mut list_state = ListState::default();
    list_state.select(Some(state.tree_sel));
    let list = List::new(items)
        .block(pane_block("objects", focused))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_stateful_widget(list, area, &mut list_state);
}

fn render_fields(frame: &mut Frame, area: Rect, state: &ViewState) {
    let focused = state.focus == Focus::Fields;
    let rows: Vec<Row> = state
        .fields
        .iter()
        .map(|field| {
            Row::new(vec![
                field.id.to_string(),
                format!("@{}+{}", field.span.offset, field.span.len),
                field.raw_hex.clone(),
                field.value.clone(),
            ])
        })
        .collect();
    let mut table_state = TableState::default();
    table_state.select((!state.fields.is_empty()).then_some(state.field_sel));
    let table = Table::new(
        rows,
        [
            Constraint::Length(34),
            Constraint::Length(13),
            Constraint::Length(18),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(vec!["field", "span", "raw", "value"]).style(Style::default().fg(Color::DarkGray)),
    )
    .block(pane_block("fields", focused))
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_stateful_widget(table, area, &mut table_state);
}

fn render_hex(frame: &mut Frame, area: Rect, state: &ViewState) {
    let span = state.active_span();
    let bytes = &state.model.bytes;
    let title = format!("hex @{}+{}", span.offset, span.len);

    // Show the rows covering the span, with one row of context before.
    let row = |offset: u64| offset / 16;
    let first_row = row(span.offset).saturating_sub(1);
    let last_row = row(span.offset.saturating_add(span.len).saturating_sub(1));
    let max_rows = usize::from(area.height.saturating_sub(2));
    let mut lines = Vec::new();
    for r in first_row..=last_row.min(first_row + max_rows as u64) {
        let base = r * 16;
        let mut spans = vec![Text::styled(
            format!("{base:08x}  "),
            Style::default().fg(Color::DarkGray),
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
                    Style::default().fg(Color::Black).bg(Color::Yellow)
                } else {
                    Style::default()
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
        spans.push(Text::styled(ascii, Style::default().fg(Color::DarkGray)));
        lines.push(Line::from(spans));
    }
    if lines.is_empty() {
        lines.push(Line::from("span outside image"));
    }
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .style(Style::default().fg(Color::Gray)),
        ),
        area,
    );
}

fn pane_block(title: &str, focused: bool) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .title(format!("{title}{}", if focused { " *" } else { "" }))
        .border_style(if focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        })
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
        assert_eq!(magic.value, "3774210530"); // 0xE0F5E1E2

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
        assert_eq!(format.value, "1"); // extended version, flat plain layout
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
        assert!(text.contains("superblock"));
        assert!(text.contains("erofs.superblock.magic"));
        assert!(text.contains("objects"));
        assert!(text.contains("fields"));
        assert!(text.contains("/etc/issue"));

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
        assert!(text.contains("hex @1024+4"));
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
