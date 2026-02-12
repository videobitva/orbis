//! Library for extracting PlayStation 4 PKG files.
//!
//! This crate provides the core extraction logic for PS4 `.pkg` files,
//! including both PKG entry extraction and inner PFS filesystem extraction.
//!
//! # Overview
//!
//! The main entry point is [`PkgExtractor`], which takes a parsed [`orbis_pkg::Pkg`]
//! and an [`ExtractProgress`] implementation, then extracts the package contents
//! to a directory on disk.
//!
//! # Example
//!
//! ```no_run
//! use orbis_pkg_util::{open_pkg, PkgExtractor, SilentProgress};
//!
//! let pkg = open_pkg("game.pkg".as_ref()).expect("failed to open PKG");
//! let extractor = PkgExtractor::new(&pkg, SilentProgress, false);
//! extractor.extract("output/").expect("extraction failed");
//! ```
//!
//! # Custom progress reporting
//!
//! You can implement the [`ExtractProgress`] trait to receive fine-grained progress
//! updates during extraction.

pub mod extract;
pub mod progress;

pub use self::extract::{ExtractError, PkgExtractor};
pub use self::progress::{ExtractProgress, SilentProgress};

#[cfg(feature = "cli")]
pub use self::progress::ConsoleProgress;

use snafu::{ResultExt, Snafu};
use std::path::Path;

/// Errors that can occur when opening a PKG file from disk.
#[derive(Debug, Snafu)]
pub enum OpenPkgError {
    #[snafu(display("failed to open file"))]
    OpenFile { source: std::io::Error },

    #[snafu(display("failed to memory map file"))]
    MmapFile { source: std::io::Error },

    #[snafu(display("failed to parse PKG"))]
    ParsePkg { source: orbis_pkg::OpenError },
}

/// Opens a PKG file from disk using a memory-mapped read.
///
/// This is a convenience function that opens the file, maps it into memory,
/// and parses the PKG header. The returned [`Pkg`](orbis_pkg::Pkg) borrows
/// from the memory map and is ready for extraction.
///
/// # Safety
///
/// This function uses `unsafe` internally to create a memory map. The caller
/// must ensure the file is not modified or truncated while the returned `Pkg`
/// is in use.
pub unsafe fn open_pkg(path: &Path) -> Result<orbis_pkg::Pkg<memmap2::Mmap>, OpenPkgError> {
    let file = std::fs::File::open(path).context(OpenFileSnafu)?;
    let raw = unsafe { memmap2::Mmap::map(&file).context(MmapFileSnafu)? };
    orbis_pkg::Pkg::new(raw).context(ParsePkgSnafu)
}
