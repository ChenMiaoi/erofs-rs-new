//! A pure Rust library for reading EROFS (Enhanced Read-Only File System) images.
//!
//! EROFS is a read-only filesystem designed for performance and space efficiency,
//! commonly used in Android and other embedded systems.
//!
//! # Features
//!
//! - **Zero-copy parsing**: Via memory maps or borrowed byte slices
//! - **Multiple backends**: Memory-mapped files, byte slices, and optional OpenDAL
//! - **Multiple layouts**: Flat plain, flat inline, and chunk-based data layouts
//! # Examples
//!
//! ## Standard usage (with std)
//!
//! ```no_run
//! use std::io::Read;
//! use erofs_rs::{EroFS, backend::MmapImage};
//!
//! // SAFETY: image file is not modified while mapped
//! let image = unsafe { MmapImage::new_from_path("image.erofs") }.unwrap();
//! let fs = EroFS::new(image).unwrap();
//!
//! // Read a file
//! let mut file = fs.open("/etc/passwd").unwrap();
//! let mut content = String::new();
//! file.read_to_string(&mut content).unwrap();
//! ```
//!
//! For OS-independent on-disk decoding and checked image offsets, use the
//! companion `erofs-format` crate. This high-level reader intentionally uses
//! the standard library for filesystem-facing APIs.

pub(crate) mod dirent;
pub(crate) mod filesystem;

pub mod r#async;
pub mod backend;
mod error;
pub mod sync;
pub mod types;

pub use dirent::DirEntry;
pub use error::*;
pub use sync::{EroFS, ReadDir, WalkDir, WalkDirEntry};
