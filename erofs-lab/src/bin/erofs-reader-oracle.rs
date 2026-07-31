use std::{env, process::ExitCode};

use erofs_rs::{EroFS, backend::MmapImage};
use serde::Serialize;

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

fn run(path: &str) -> Result<Stats, (&'static str, &'static str)> {
    // SAFETY: image file is not modified while mapped
    let image = unsafe { MmapImage::new_from_path(path) }.map_err(|_| ("open", "image_open"))?;
    let fs = EroFS::new(image).map_err(|_| ("superblock", "superblock_parse"))?;
    let mut stats = Stats::default();
    let walker = fs
        .walk_dir("/")
        .map_err(|_| ("readdir", "root_directory"))?;
    for result in walker {
        let entry = result.map_err(|_| ("traverse", "directory_entry"))?;
        stats.nodes = stats.nodes.checked_add(1).ok_or(("traverse", "budget"))?;
        if stats.nodes > 100_000 || entry.depth > 256 {
            return Err(("traverse", "budget"));
        }
        if entry.inode.is_file() {
            stats.regular_files += 1;
            let mut file = fs
                .open_inode_file(entry.inode)
                .map_err(|_| ("read_data", "file_open"))?;
            let copied = std::io::copy(&mut file, &mut std::io::sink())
                .map_err(|_| ("read_data", "file_read"))?;
            stats.bytes_read = stats
                .bytes_read
                .checked_add(copied)
                .ok_or(("read_data", "budget"))?;
        } else if entry.inode.is_symlink() {
            stats.symlinks += 1;
            let mut target = fs
                .open_inode_data(entry.inode)
                .map_err(|_| ("read_data", "symlink_open"))?;
            let copied = std::io::copy(&mut target, &mut std::io::sink())
                .map_err(|_| ("read_data", "symlink_read"))?;
            stats.bytes_read = stats
                .bytes_read
                .checked_add(copied)
                .ok_or(("read_data", "budget"))?;
        }
    }
    Ok(stats)
}

fn main() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: erofs-reader-oracle IMAGE");
        return ExitCode::from(2);
    };
    let mut stats = Stats::default();
    event("open", "started", None, &stats);
    match run(&path) {
        Ok(result) => {
            stats = result;
            event("traverse", "accepted", None, &stats);
            event("complete", "accepted", None, &stats);
            ExitCode::SUCCESS
        }
        Err((phase, class)) => {
            event(phase, "rejected", Some(class), &stats);
            ExitCode::from(1)
        }
    }
}
