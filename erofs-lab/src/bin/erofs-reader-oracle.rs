use std::{env, process::ExitCode};

use erofs_rs::{EroFS, backend::MmapImage};
use serde::Serialize;

/// Total bytes streamed from file and symlink data before the traversal
/// stops. Matches the 1 GiB `max_image_bytes` campaign budget: a single
/// image holds at most that much unique payload, so streaming more implies
/// pathological inode sharing that the 20 s CPU rlimit would otherwise only
/// catch after the fact.
const TOTAL_BYTE_BUDGET: u64 = 1 << 30;

#[derive(Serialize)]
struct Event<'a> {
    schema: &'static str,
    phase: &'a str,
    status: &'a str,
    error_class: Option<&'a str>,
    nodes: u64,
    regular_files: u64,
    symlinks: u64,
    bytes_read: u64,
}

fn event(phase: &str, status: &str, error_class: Option<&str>, stats: &Stats) {
    println!(
        "{}",
        serde_json::to_string(&Event {
            schema: "erofs-rust-oracle-event/v1",
            phase,
            status,
            error_class,
            nodes: stats.nodes,
            regular_files: stats.regular_files,
            symlinks: stats.symlinks,
            bytes_read: stats.bytes_read,
        })
        .expect("event serialization")
    );
}

#[derive(Default)]
struct Stats {
    nodes: u64,
    regular_files: u64,
    symlinks: u64,
    bytes_read: u64,
}

fn run(path: &str, stats: &mut Stats) -> Result<(), (&'static str, &'static str, &'static str)> {
    // SAFETY: image file is not modified while mapped
    let image = unsafe { MmapImage::new_from_path(path) }
        .map_err(|_| ("open", "rejected", "image_open"))?;
    let fs = EroFS::new(image).map_err(|_| ("superblock", "rejected", "superblock_parse"))?;
    let walker = fs
        .walk_dir("/")
        .map_err(|_| ("readdir", "rejected", "root_directory"))?;
    for result in walker {
        let entry = result.map_err(|_| ("traverse", "rejected", "directory_entry"))?;
        stats.nodes = stats
            .nodes
            .checked_add(1)
            .ok_or(("traverse", "rejected", "budget"))?;
        if stats.nodes > 100_000 || entry.depth > 256 {
            return Err(("traverse", "rejected", "budget"));
        }
        if entry.inode.is_file() {
            stats.regular_files += 1;
            let mut file = fs
                .open_inode_file(entry.inode)
                .map_err(|_| ("read_data", "rejected", "file_open"))?;
            let copied = std::io::copy(&mut file, &mut std::io::sink())
                .map_err(|_| ("read_data", "rejected", "file_read"))?;
            stats.bytes_read =
                stats
                    .bytes_read
                    .checked_add(copied)
                    .ok_or(("read_data", "rejected", "budget"))?;
        } else if entry.inode.is_symlink() {
            stats.symlinks += 1;
            let mut target = fs
                .open_inode_data(entry.inode)
                .map_err(|_| ("read_data", "rejected", "symlink_open"))?;
            let copied = std::io::copy(&mut target, &mut std::io::sink())
                .map_err(|_| ("read_data", "rejected", "symlink_read"))?;
            stats.bytes_read =
                stats
                    .bytes_read
                    .checked_add(copied)
                    .ok_or(("read_data", "rejected", "budget"))?;
        }
        if stats.bytes_read > TOTAL_BYTE_BUDGET {
            return Err(("complete", "resource_exhausted", "byte_budget"));
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    // Hooks run for unwind (debug) and abort (release) panics alike, so the
    // classifier sees the same crash event regardless of build profile.
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|location| format!("{}:{}", location.file(), location.line()))
            .unwrap_or_else(|| "unknown".into());
        println!(
            "{}",
            serde_json::json!({
                "schema": "erofs-reader-oracle/v1",
                "phase": "panic",
                "status": "crashed",
                "error_class": format!("panic at {location}"),
            })
        );
        eprintln!("{info}");
    }));
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: erofs-reader-oracle IMAGE");
        return ExitCode::from(2);
    };
    let mut stats = Stats::default();
    event("open", "started", None, &stats);
    match run(&path, &mut stats) {
        Ok(()) => {
            event("traverse", "accepted", None, &stats);
            event("complete", "accepted", None, &stats);
            ExitCode::SUCCESS
        }
        Err((phase, status, class)) => {
            event(phase, status, Some(class), &stats);
            ExitCode::from(1)
        }
    }
}
