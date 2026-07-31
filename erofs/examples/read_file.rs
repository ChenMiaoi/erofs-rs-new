use std::{
    env,
    io::{Read, Write},
    process::ExitCode,
};

use erofs_rs::{EroFS, backend::MmapImage};

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let image = args.next().ok_or("usage: read_file IMAGE PATH")?;
    let path = args.next().ok_or("usage: read_file IMAGE PATH")?;
    if args.next().is_some() {
        return Err("usage: read_file IMAGE PATH".into());
    }

    // SAFETY: image file is not modified while mapped
    let image = unsafe { MmapImage::new_from_path(image)? };
    let fs = EroFS::new(image)?;
    let mut file = fs.open(path)?;
    let mut bytes = Vec::with_capacity(file.size());
    file.read_to_end(&mut bytes)?;
    std::io::stdout().write_all(&bytes)?;
    Ok(ExitCode::SUCCESS)
}
