use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, Local};
use clap::{Args, Subcommand};
use erofs_rs::{
    EroFS,
    r#async::EroFS as AsyncEroFS,
    backend::{AsyncImage, Image, MmapImage, OpendalImage},
    types::Inode,
};
use opendal::{Operator, services};
use url::Position;

#[derive(Args, Debug)]
pub struct InspectArgs {
    #[clap(short, long)]
    image: String,

    #[command(subcommand)]
    operation: InspectSubcommands,
}

#[derive(Subcommand, Debug)]
enum InspectSubcommands {
    Ls {
        #[clap(default_value = "/")]
        path: String,
    },
    Cat {
        path: String,
    },
}

pub async fn inspect(args: InspectArgs) -> Result<()> {
    // Treat the image as remote only if it parses as an http(s) URL; anything
    // else (including local files named http*) is a local path.
    let url = crate::remote_url(&args.image);
    if let Some(u) = url {
        // Async path for remote files
        let builder = services::Http::default().endpoint(&u[..Position::BeforePath]);
        let op = Operator::new(builder)?.finish();
        let image = OpendalImage::new(op, u.path().to_string());
        let fs = AsyncEroFS::new(image).await?;

        match args.operation {
            InspectSubcommands::Ls { path } => ls_async(&fs, &path).await?,
            InspectSubcommands::Cat { path } => cat_async(&fs, &path).await?,
        }
    } else {
        // Sync path for local files
        // SAFETY: the image file is opened read-only and not modified while mapped
        let image = unsafe { MmapImage::new_from_path(args.image)? };
        let fs = EroFS::new(image)?;

        match args.operation {
            InspectSubcommands::Ls { path } => ls(&fs, &path)?,
            InspectSubcommands::Cat { path } => cat(&fs, &path)?,
        }
    }

    Ok(())
}

fn format_mode(inode: &Inode) -> String {
    let mut res = String::with_capacity(10);
    res.push(if inode.is_dir() { 'd' } else { '-' });

    let masks = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'), // User
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'), // Group
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'), // Other
    ];

    let mode = inode.permissions().mode();
    for (mask, char) in masks {
        if mode & mask != 0 {
            res.push(char);
        } else {
            res.push('-');
        }
    }

    res
}

fn format_size(inode: &Inode) -> String {
    let size = inode.data_size();
    if size < 1024 {
        format!("{}B", size)
    } else if size < 1024 * 1024 {
        format!("{:.1}KiB", size as f64 / 1024.0)
    } else if size < 1024 * 1024 * 1024 {
        format!("{:.1}MiB", size as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1}GB", size as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn format_time(inode: &Inode) -> String {
    let t = match inode.modified() {
        Some(t) => t,
        None => return String::from(""),
    };

    let dt: DateTime<Local> = t.into();
    let now = Local::now();
    if dt.year() == now.year() {
        dt.format("%b %e %H:%M").to_string()
    } else {
        dt.format("%b %e  %Y").to_string()
    }
}

/// Escapes control and other non-printable characters in an image-derived
/// name so it cannot inject terminal escape sequences when printed.
fn sanitize_name(name: &str) -> String {
    name.chars().flat_map(char::escape_debug).collect()
}

fn ls<I: Image>(fs: &EroFS<I>, path: &str) -> Result<()> {
    let read_dir = fs
        .read_dir(path)
        .with_context(|| format!("failed to read directory: {}", path))?;

    for entry in read_dir {
        let entry = entry.with_context(|| "failed to read directory entry")?;
        let inode = entry.inode;
        println!(
            "{} {:>8} {} {}",
            format_mode(&inode),
            format_size(&inode),
            format_time(&inode),
            sanitize_name(entry.dir_entry.file_name())
        );
    }

    Ok(())
}

fn cat<I: Image>(fs: &EroFS<I>, path: &str) -> Result<()> {
    let mut file = fs
        .open(path)
        .with_context(|| format!("failed to open file: {}", path))?;

    if file.size() > 1024 * 1024 {
        return Err(anyhow::anyhow!("file too large to output (>{} MiB)", 1));
    }

    std::io::copy(&mut file, &mut std::io::stdout())?;
    Ok(())
}

async fn ls_async<I: AsyncImage>(fs: &AsyncEroFS<I>, path: &str) -> Result<()> {
    let mut read_dir = fs
        .read_dir(path)
        .await
        .with_context(|| format!("failed to read directory: {}", path))?;

    while let Some(result) = read_dir.next_entry().await {
        let entry = result.with_context(|| "failed to read directory entry")?;
        let inode = entry.inode;
        println!(
            "{} {:>8} {} {}",
            format_mode(&inode),
            format_size(&inode),
            format_time(&inode),
            sanitize_name(entry.dir_entry.file_name())
        );
    }

    Ok(())
}

async fn cat_async<I: AsyncImage>(fs: &AsyncEroFS<I>, path: &str) -> Result<()> {
    let mut file = fs
        .open(path)
        .await
        .with_context(|| format!("failed to open file: {}", path))?;

    if file.size() > 1024 * 1024 {
        return Err(anyhow::anyhow!("file too large to output (>{} MiB)", 1));
    }

    let mut buffer = vec![0u8; 4096];
    let mut stdout = std::io::stdout();

    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        std::io::Write::write_all(&mut stdout, &buffer[..n])?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::sanitize_name;

    #[test]
    fn sanitize_name_leaves_printable_names_untouched() {
        assert_eq!(sanitize_name("plain file.txt"), "plain file.txt");
    }

    #[test]
    fn sanitize_name_escapes_control_characters() {
        assert_eq!(sanitize_name("evil\u{1b}[2J"), "evil\\u{1b}[2J");
        assert_eq!(sanitize_name("new\nline"), "new\\nline");
        assert_eq!(sanitize_name("carriage\rreturn"), "carriage\\rreturn");
    }
}
