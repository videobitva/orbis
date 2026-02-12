use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use std::fmt::{Display, Formatter};

use snafu::{OptionExt, Snafu, ensure};

/// Errors when parsing a PFS header from bytes.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ReadError {
    #[snafu(display("invalid version"))]
    InvalidVersion,

    #[snafu(display("invalid format"))]
    InvalidFormat,

    #[snafu(display("too many blocks for inodes"))]
    TooManyInodeBlocks,

    #[snafu(display("source buffer is too short to read the header"))]
    ReadHeaderFailed,

    #[snafu(display("source buffer is too short to read the key seed"))]
    ReadKeySeedFailed,
}

use zerocopy::byteorder::little_endian::{U16, U32, U64};

const VERSION: u64 = 1;
const FORMAT: u64 = 20130315;

/// The size of the full PFS header on disk (includes key seed area).
pub(crate) const HEADER_SIZE: usize = 0x380;

/// Contains PFS header.
///
/// See https://www.psdevwiki.com/ps4/PFS#Header.2FSuperblock for some basic information.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct PfsHeaderRaw {
    version: U64,       // 0x00
    format: U64,        // 0x08
    id: U64,            // 0x10
    flags: FlagsRaw,    // 0x18
    mode: Mode,         // 0x1C
    unknown: U16,       // 0x1E (unknown)
    block_size: U32,    // 0x20
    nbackup: U32,       // 0x24
    nblock: U64,        // 0x28
    ndinode: U64,       // 0x30 - Number of inodes in the inode blocks
    ndblock: U64,       // 0x38 - Number of data blocks
    ndinodeblock: U64,  // 0x40 - Number of inode blocks
    superroot_ino: U64, // 0x48
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct FlagsRaw {
    fmode: u8,
    clean: u8,
    ronly: u8,
    rsv: u8,
}

pub(crate) struct PfsHeader {
    raw_header: PfsHeaderRaw,
    key_seed: [u8; 16],
}

impl PfsHeader {
    /// Parses the header directly from a byte slice.
    ///
    /// The slice must be at least [`HEADER_SIZE`] bytes.
    pub(super) fn from_bytes(data: &[u8]) -> Result<Self, ReadError> {
        let (raw_header, rest) =
            PfsHeaderRaw::read_from_prefix(data).map_err(|_| ReadHeaderFailedSnafu.build())?;

        // Check version.
        ensure!(raw_header.version.get() == VERSION, InvalidVersionSnafu);

        // Check format.
        ensure!(raw_header.format.get() == FORMAT, InvalidFormatSnafu);

        // Usually block will be references by u32. Not sure why ndinodeblock is 64-bits. Design flaws?
        ensure!(
            raw_header.ndinodeblock.get() <= (u32::MAX as u64),
            TooManyInodeBlocksSnafu
        );

        // Read key seed from the rest of the header.
        let key_seed_offset = 0x370 - size_of::<PfsHeaderRaw>();
        let key_seed: [u8; 16] = rest
            .get(key_seed_offset..key_seed_offset + 16)
            .context(ReadKeySeedFailedSnafu)?
            .try_into()
            .unwrap();

        Ok(Self {
            raw_header,
            key_seed,
        })
    }

    pub fn mode(&self) -> Mode {
        self.raw_header.mode
    }

    pub fn block_size(&self) -> u32 {
        self.raw_header.block_size.get()
    }

    /// Gets a number of total inodes.
    pub fn inode_count(&self) -> usize {
        self.raw_header.ndinode.get() as usize
    }

    /// Gets a number of blocks containing inode (not a number of inode).
    pub fn inode_block_count(&self) -> u32 {
        self.raw_header.ndinodeblock.get() as u32
    }

    pub fn super_root_inode(&self) -> usize {
        self.raw_header.superroot_ino.get() as usize
    }

    pub fn key_seed(&self) -> &[u8; 16] {
        &self.key_seed
    }
}

/// Contains PFS flags.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C)]
pub struct Mode {
    flags: U16,
}

impl Mode {
    /// Returns `true` if the PFS is signed.
    #[inline]
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.flags.get() & 0x1 != 0
    }

    #[inline]
    #[must_use]
    pub const fn is_64bits(&self) -> bool {
        self.flags.get() & 0x2 != 0
    }

    /// Returns `true` if the PFS is encrypted.
    #[inline]
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.flags.get() & 0x4 != 0
    }
}

impl Display for Mode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{:x}", self.flags.get())?;

        let mut op = false;

        let mut first = true;

        let mut flag = |name: &str| -> std::fmt::Result {
            if !op {
                f.write_str(" (")?;
                op = true;
            }

            if !first {
                f.write_str(", ")?;
            }

            f.write_str(name)?;
            first = false;

            Ok(())
        };

        if self.is_signed() {
            flag("signed")?;
        }

        if self.is_64bits() {
            flag("64-bits")?;
        }

        if self.is_encrypted() {
            flag("encrypted")?;
        }

        if op {
            f.write_str(")")?;
        }

        Ok(())
    }
}
