use erofs_format::schema::{FIELDS, SCHEMA_IDENTITY};

fn main() {
    println!("schema API: {}", SCHEMA_IDENTITY.api);
    println!("Linux source: {}", SCHEMA_IDENTITY.linux_commit);
    println!("field count: {}", FIELDS.len());
    for field in FIELDS {
        println!(
            "{}\t{:?}\t{}+{}\t{:?}",
            field.id, field.structure, field.storage.offset, field.storage.len, field.encoding
        );
    }
}
