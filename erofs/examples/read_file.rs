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

    let fs = EroFS::new(MmapImage::new_from_path(image)?)?;
    let mut file = fs.open(path)?;
    let mut bytes = Vec::with_capacity(file.size());
    file.read_to_end(&mut bytes)?;
    std::io::stdout().write_all(&bytes)?;
    Ok(ExitCode::SUCCESS)
}
