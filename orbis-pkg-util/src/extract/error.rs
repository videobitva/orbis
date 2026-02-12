use snafu::Snafu;
use std::path::PathBuf;

/// Errors that can occur during PKG extraction.
#[derive(Debug, Snafu)]
pub enum ExtractError {
    // Entry extraction errors
    #[snafu(display("failed to read entry #{num}: {source}"))]
    ReadEntryFailed {
        num: usize,
        source: orbis_pkg::EntryReadError,
    },

    #[snafu(display("failed to get data for entry #{num}: {source}"))]
    GetEntryDataFailed {
        num: usize,
        source: orbis_pkg::EntryDataError,
    },

    #[snafu(display("cannot create directory {}: {source}", path.display()))]
    CreateDirectoryFailed {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("cannot create file {}: {source}", path.display()))]
    CreateFileFailed {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("cannot write to {}: {source}", path.display()))]
    WriteFailed {
        path: PathBuf,
        source: std::io::Error,
    },

    // PFS extraction errors
    #[snafu(display("PKG does not contain a PFS image"))]
    NoPfsImage,

    #[snafu(display("cannot open outer PFS: {source}"))]
    OpenOuterPfsFailed { source: orbis_pfs::OpenSliceError },

    #[snafu(display("cannot open super-root on outer PFS: {source}"))]
    OpenOuterSuperRootFailed {
        source: orbis_pfs::directory::OpenError,
    },

    #[snafu(display("outer PFS does not contain uroot directory"))]
    NoOuterUroot,

    #[snafu(display("cannot open uroot on outer PFS: {source}"))]
    OpenOuterUrootFailed {
        source: orbis_pfs::directory::OpenError,
    },

    #[snafu(display("outer PFS does not contain pfs_image.dat"))]
    NoInnerImage,

    #[snafu(display("cannot create decompressor for inner PFS: {source}"))]
    CreateDecompressorFailed { source: orbis_pfs::pfsc::OpenError },

    #[snafu(display("cannot open inner PFS: {source}"))]
    OpenInnerPfsFailed { source: orbis_pfs::OpenImageError },

    #[snafu(display("cannot open super-root on inner PFS: {source}"))]
    OpenInnerSuperRootFailed {
        source: orbis_pfs::directory::OpenError,
    },

    #[snafu(display("inner PFS does not contain uroot directory"))]
    NoInnerUroot,

    #[snafu(display("cannot open directory {path} on PFS: {source}"))]
    OpenPfsDirectoryFailed {
        path: String,
        source: orbis_pfs::directory::OpenError,
    },

    #[snafu(display("unsupported file name in PFS path: {path}"))]
    UnsupportedFileName { path: String },

    #[snafu(display("cannot read {path} from PFS: {source}"))]
    ReadPfsFileFailed {
        path: String,
        source: std::io::Error,
    },
}
