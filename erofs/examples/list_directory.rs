use std::{env, process::ExitCode};

use erofs_rs::{EroFS, backend::MmapImage};

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let image = args.next().ok_or("usage: list_directory IMAGE DIRECTORY")?;
    let path = args.next().ok_or("usage: list_directory IMAGE DIRECTORY")?;
    if args.next().is_some() {
        return Err("usage: list_directory IMAGE DIRECTORY".into());
    }

    let fs = EroFS::new(MmapImage::new_from_path(image)?)?;
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
