use std::{env, fs};

use erofs_format::{
    SliceReader,
    locator::{Locator, ObjectRef},
    schema::field_by_id,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let image = env::args().nth(1).ok_or("usage: locate_superblock IMAGE")?;
    let bytes = fs::read(image)?;
    let reader = SliceReader::new(&bytes);
    let locator = Locator::new(&reader).map_err(|error| format!("{error:?}"))?;
    let field = field_by_id("erofs.superblock.magic").ok_or("schema field is missing")?;
    let occurrence = locator
        .locate(ObjectRef::Superblock, field)
        .map_err(|error| format!("{error:?}"))?;

    println!("field: {}", occurrence.field.id);
    println!("span: {}+{}", occurrence.span.offset, occurrence.span.len);
    println!("value: {:?}", occurrence.value);
    Ok(())
}
