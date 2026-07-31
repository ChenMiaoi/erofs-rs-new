use std::{env, process::ExitCode};

use erofs_rs::{EroFS, backend::MmapImage};

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let image = args.next().ok_or("usage: list_directory IMAGE DIRECTORY")?;
    let path = args.next().ok_or("usage: list_directory IMAGE DIRECTORY")?;
    if args.next().is_some() {
        return Err("usage: list_directory IMAGE DIRECTORY".into());
    }

    // SAFETY: image file is not modified while mapped
    let image = unsafe { MmapImage::new_from_path(image)? };
    let fs = EroFS::new(image)?;
    for entry in fs.read_dir(path)? {
        let entry = entry?;
        println!(
            "{:?}\t{:?}",
            entry.dir_entry.path(),
            entry.dir_entry.file_type()
        );
    }
    Ok(ExitCode::SUCCESS)
}
