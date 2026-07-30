use std::{env, fs, path::Path};

use erofs_lab::{IntegrityPolicy, MutationIntent, MutationMode, materialize, plan, replay};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let parent_path = args.next().ok_or("usage: mutate_and_replay IMAGE CORPUS")?;
    let corpus = args.next().ok_or("usage: mutate_and_replay IMAGE CORPUS")?;
    if args.next().is_some() {
        return Err("usage: mutate_and_replay IMAGE CORPUS".into());
    }

    let parent = fs::read(&parent_path)?;
    let resolved = plan(
        &parent,
        &[MutationIntent::PatchBytes {
            offset: 0,
            bytes: vec![0],
        }],
        MutationMode::Raw,
        IntegrityPolicy::Preserve,
    )?;
    let sample = materialize(Path::new(&parent_path), Path::new(&corpus), &resolved)?;
    let replayed = replay(
        Path::new(&parent_path),
        Path::new(&corpus),
        &sample.manifest,
    )?;

    println!("sample: {}", sample.manifest.display());
    println!("replayed: {}", replayed.manifest.display());
    Ok(())
}
