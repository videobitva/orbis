use crate::image::Image;

use snafu::{ResultExt, Snafu, ensure};
use zerocopy::{
    FromBytes, Immutable, KnownLayout,
    little_endian::{U16, U32, U64},
};

/// Raw inode header (100 bytes).
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct InodeRaw {
    /// 0x00: Inode mode (file=0x8000, dir=0x4000).
    pub mode: U16,
    /// 0x02: Number of links.
    pub nlink: U16,
    /// 0x04: Flags (compressed, readonly, etc.).
    pub flags: U32,
    /// 0x08: Size in bytes.
    pub size: U64,
    /// 0x10: Compressed size (same as size for uncompressed).
    pub size_compressed: U64,
    /// 0x18: Access time.
    pub atime: U64,
    /// 0x20: Modification time.
    pub mtime: U64,
    /// 0x28: Change time.
    pub ctime: U64,
    /// 0x30: Creation time.
    pub birthtime: U64,
    /// 0x38: Modification time nanoseconds.
    pub mtimensec: U32,
    /// 0x3C: Access time nanoseconds.
    pub atimensec: U32,
    /// 0x40: Change time nanoseconds.
    pub ctimensec: U32,
    /// 0x44: Creation time nanoseconds.
    pub birthnsec: U32,
    /// 0x48: User ID.
    pub uid: U32,
    /// 0x4C: Group ID.
    pub gid: U32,
    /// 0x50: Reserved.
    pub spare: [u8; 16],
    /// 0x60: Number of blocks.
    pub blocks: U32,
}

/// Errors when loading inode blocks.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum LoadBlocksError {
    #[snafu(display("cannot read block #{block}"))]
    Read { block: u32, source: std::io::Error },

    #[snafu(display("block #{block} does not exist"))]
    NotExists { block: u32 },

    #[snafu(display("double indirect block is not supported for inode #{inode}"))]
    DoubleIndirectBlockNotSupported { inode: usize },
}

/// Contains information for an inode.
pub struct Inode {
    index: usize,
    raw: InodeRaw,
    direct_blocks: [u32; 12],
    #[allow(dead_code)] // Reserved for future signature verification
    direct_sigs: [Option<[u8; 32]>; 12],
    indirect_blocks: [u32; 5],
    #[allow(dead_code)] // Reserved for future signature verification
    indirect_sigs: [Option<[u8; 32]>; 5],
    /// Whether this inode uses signed (36-byte) indirect block entries.
    /// When `false`, indirect entries are plain 4-byte block pointers.
    signed: bool,
}

impl Inode {
    fn blocks(&self) -> u32 {
        self.raw.blocks.get()
    }

    /// If the inode's data blocks are contiguous, returns `(start_block, block_count)`.
    ///
    /// Returns `None` if the blocks are non-contiguous, require indirect lookups,
    /// or the inode has no blocks.
    pub(crate) fn contiguous_blocks(&self) -> Option<(u32, u32)> {
        let count = self.blocks();

        if count == 0 {
            return None;
        }

        // Explicitly marked as contiguous.
        if self.direct_blocks[1] == 0xffffffff {
            return Some((self.direct_blocks[0], count));
        }

        // Single block is trivially contiguous.
        if count == 1 {
            return Some((self.direct_blocks[0], 1));
        }

        None
    }

    pub(super) fn from_raw32_unsigned(index: usize, src: &mut &[u8]) -> Result<Self, FromRawError> {
        // Parse header directly from slice.
        let (raw, rest) = InodeRaw::read_from_prefix(src).map_err(|_| FromRawError::TooSmall)?;
        *src = rest;

        // Read block pointers (12 direct + 5 indirect = 17 × 4 = 68 bytes).
        ensure!(src.len() >= 68, from_raw_error::TooSmallSnafu);

        let block_data = &src[..68];
        *src = &src[68..];

        let mut direct_blocks = [0u32; 12];
        let mut indirect_blocks = [0u32; 5];

        for (i, block) in direct_blocks.iter_mut().enumerate() {
            let offset = i * 4;
            *block = u32::from_le_bytes(block_data[offset..offset + 4].try_into().unwrap());
        }

        for (i, block) in indirect_blocks.iter_mut().enumerate() {
            let offset = 48 + i * 4;
            *block = u32::from_le_bytes(block_data[offset..offset + 4].try_into().unwrap());
        }

        Ok(Self {
            index,
            raw,
            direct_blocks,
            direct_sigs: [None; 12],
            indirect_blocks,
            indirect_sigs: [None; 5],
            signed: false,
        })
    }

    pub(super) fn from_raw32_signed(index: usize, src: &mut &[u8]) -> Result<Self, FromRawError> {
        // Parse header directly from slice.
        let (raw, rest) = InodeRaw::read_from_prefix(src).map_err(|_| FromRawError::TooSmall)?;
        *src = rest;

        // Read block pointers with signatures.
        // 12 direct: 12 × (32 sig + 4 ptr) = 432 bytes
        // 5 indirect: 5 × (32 sig + 4 ptr) = 180 bytes
        // Total: 612 bytes
        ensure!(src.len() >= 612, from_raw_error::TooSmallSnafu);

        let block_data = &src[..612];
        *src = &src[612..];

        let mut direct_blocks = [0u32; 12];
        let mut direct_sigs: [Option<[u8; 32]>; 12] = [None; 12];
        let mut indirect_blocks = [0u32; 5];
        let mut indirect_sigs: [Option<[u8; 32]>; 5] = [None; 5];

        let mut offset = 0;
        for (sig, block) in direct_sigs.iter_mut().zip(direct_blocks.iter_mut()) {
            *sig = Some(block_data[offset..offset + 32].try_into().unwrap());
            *block = u32::from_le_bytes(block_data[offset + 32..offset + 36].try_into().unwrap());
            offset += 36;
        }

        for (sig, block) in indirect_sigs.iter_mut().zip(indirect_blocks.iter_mut()) {
            *sig = Some(block_data[offset..offset + 32].try_into().unwrap());
            *block = u32::from_le_bytes(block_data[offset + 32..offset + 36].try_into().unwrap());
            offset += 36;
        }

        Ok(Self {
            index,
            raw,
            direct_blocks,
            direct_sigs,
            indirect_blocks,
            indirect_sigs,
            signed: true,
        })
    }

    /// Loads the block map for this inode using positional reads.
    ///
    /// Returns a vector mapping logical block index -> physical block number.
    pub fn load_block_map(
        &self,
        image: &dyn Image,
        block_size: u32,
    ) -> Result<Vec<u32>, LoadBlocksError> {
        let block_count = self.blocks() as usize;
        let mut blocks: Vec<u32> = Vec::with_capacity(block_count);

        if block_count == 0 {
            return Ok(blocks);
        }

        // Check if inode uses contiguous blocks.
        if self.direct_blocks[1] == 0xffffffff {
            let start = self.direct_blocks[0];
            for block in start..(start + self.blocks()) {
                blocks.push(block);
            }
            return Ok(blocks);
        }

        // Load direct pointers.
        for i in 0..12 {
            blocks.push(self.direct_blocks[i]);
            if blocks.len() == block_count {
                return Ok(blocks);
            }
        }

        let bs = block_size as u64;

        // Load indirect 0.
        let block_num = self.indirect_blocks[0];
        let offset = (block_num as u64) * bs;

        let mut block0 = vec![0; block_size as usize];

        image
            .read_exact_at(offset, &mut block0)
            .context(ReadSnafu { block: block_num })?;

        let mut data = block0.as_slice();

        while let Some(i) = self.read_indirect(&mut data) {
            blocks.push(i);
            if blocks.len() == block_count {
                return Ok(blocks);
            }
        }

        // Load indirect 1 (double indirect).
        let block_num = self.indirect_blocks[1];
        let offset = (block_num as u64) * bs;

        image
            .read_exact_at(offset, &mut block0)
            .context(ReadSnafu { block: block_num })?;

        let mut block1 = vec![0; block_size as usize];
        let mut data0 = block0.as_slice();

        while let Some(i) = self.read_indirect(&mut data0) {
            let offset = (i as u64) * bs;

            image
                .read_exact_at(offset, &mut block1)
                .context(ReadSnafu { block: block_num })?;

            let mut data1 = block1.as_slice();

            while let Some(j) = self.read_indirect(&mut data1) {
                blocks.push(j);
                if blocks.len() == block_count {
                    return Ok(blocks);
                }
            }
        }

        DoubleIndirectBlockNotSupportedSnafu { inode: self.index }.fail()
    }

    /// Reads one indirect block pointer from `raw`, advancing past the entry.
    ///
    /// For unsigned inodes the entry is a plain 4-byte LE u32.
    /// For signed inodes the entry is a 32-byte signature followed by a 4-byte LE u32.
    fn read_indirect(&self, raw: &mut &[u8]) -> Option<u32> {
        let (entry_size, value_offset) = if self.signed { (36, 32) } else { (4, 0) };

        if raw.len() < entry_size {
            return None;
        }

        let value = u32::from_le_bytes(raw[value_offset..value_offset + 4].try_into().unwrap());
        *raw = &raw[entry_size..];
        Some(value)
    }

    pub fn mode(&self) -> u16 {
        self.raw.mode.get()
    }

    pub fn flags(&self) -> InodeFlags {
        InodeFlags(self.raw.flags.get())
    }

    pub fn size(&self) -> u64 {
        self.raw.size.get()
    }

    pub fn compressed_len(&self) -> u64 {
        self.raw.size_compressed.get()
    }

    pub fn atime(&self) -> u64 {
        self.raw.atime.get()
    }

    pub fn mtime(&self) -> u64 {
        self.raw.mtime.get()
    }

    pub fn ctime(&self) -> u64 {
        self.raw.ctime.get()
    }

    pub fn birthtime(&self) -> u64 {
        self.raw.birthtime.get()
    }

    pub fn mtimensec(&self) -> u32 {
        self.raw.mtimensec.get()
    }

    pub fn atimensec(&self) -> u32 {
        self.raw.atimensec.get()
    }

    pub fn ctimensec(&self) -> u32 {
        self.raw.ctimensec.get()
    }

    pub fn birthnsec(&self) -> u32 {
        self.raw.birthnsec.get()
    }

    pub fn uid(&self) -> u32 {
        self.raw.uid.get()
    }

    pub fn gid(&self) -> u32 {
        self.raw.gid.get()
    }

    pub const fn raw(&self) -> &InodeRaw {
        &self.raw
    }
}

/// Flags of the inode.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct InodeFlags(u32);

impl InodeFlags {
    pub fn is_compressed(self) -> bool {
        self.0 & 0x00000001 != 0
    }

    pub fn value(self) -> u32 {
        self.0
    }
}

/// Errors when parsing an inode from raw bytes.
#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
pub enum FromRawError {
    /// I/O operation failed.
    #[snafu(display("i/o failed"))]
    IoFailed { source: std::io::Error },
    /// Input data was too small.
    #[snafu(display("data too small"))]
    TooSmall,
}
