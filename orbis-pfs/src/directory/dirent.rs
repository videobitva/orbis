use std::io::Read;

use snafu::{Snafu, ensure};
use zerocopy::{FromBytes, Immutable, KnownLayout, little_endian::U32};

/// Errors when reading a directory entry.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ReadError {
    #[snafu(display("i/o failed"))]
    IoFailed { source: std::io::Error },

    #[snafu(display("data too small"))]
    TooSmall,

    #[snafu(display("end of entry"))]
    EndOfEntry,
}

impl From<std::io::Error> for ReadError {
    fn from(v: std::io::Error) -> Self {
        if v.kind() == std::io::ErrorKind::UnexpectedEof {
            ReadError::TooSmall
        } else {
            ReadError::IoFailed { source: v }
        }
    }
}

/// Raw directory entry header (16 bytes).
///
/// https://www.psdevwiki.com/ps4/PFS#Dirents
#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C)]
struct DirentRaw {
    ino: U32,
    ty: U32,
    namelen: U32,
    entsize: U32,
}

pub(crate) struct Dirent {
    raw: DirentRaw,
    name: Vec<u8>,
}

impl Dirent {
    pub const FILE: u32 = 2;
    pub const DIRECTORY: u32 = 3;
    pub const SELF: u32 = 4;
    pub const PARENT: u32 = 5;

    pub fn read<F: Read>(from: &mut F) -> Result<Self, ReadError> {
        // Read fixed header.
        let mut header_buf = [0u8; size_of::<DirentRaw>()];
        from.read_exact(&mut header_buf)?;

        let raw =
            DirentRaw::read_from_bytes(&header_buf).expect("header buffer is correctly sized");

        ensure!(raw.entsize.get() != 0, EndOfEntrySnafu);

        // Read name.
        let mut name = vec![0u8; raw.namelen.get() as usize];
        from.read_exact(&mut name)?;

        Ok(Self { raw, name })
    }

    pub const fn inode(&self) -> usize {
        self.raw.ino.get() as usize
    }

    pub const fn ty(&self) -> u32 {
        self.raw.ty.get()
    }

    pub const fn name(&self) -> &[u8] {
        self.name.as_slice()
    }

    /// Returns the padding size after the name
    pub fn padding_size(&self) -> usize {
        self.raw.entsize.get() as usize - size_of::<DirentRaw>() - self.name.len()
    }
}
