use flate2::FlushDecompress;
use std::cmp::min;
use std::io::{self, ErrorKind};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout,
    little_endian::{U32, U64},
};

use crate::image::Image;
use snafu::{Snafu, ensure};

/// PFSC header (48 bytes).
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
struct PfscHeader {
    /// 0x00: Magic bytes "PFSC"
    magic: [u8; 4],
    /// 0x04: Unknown
    _unknown_04: U32,
    /// 0x08: Unknown
    _unknown_08: U32,
    /// 0x0C: Compressed block size
    block_size: U32,
    /// 0x10: Original block size
    block_size2: U64,
    /// 0x18: Offset to block mapping table
    block_offsets: U64,
    /// 0x20: Unknown
    _unknown_20: U64,
    /// 0x28: Original (uncompressed) data length
    data_length: U64,
}

const PFSC_MAGIC: &[u8; 4] = b"PFSC";

/// Errors when opening a PFSC compressed file.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum OpenError {
    #[snafu(display("i/o failed"))]
    IoFailed { source: std::io::Error },

    #[snafu(display("data too small"))]
    TooSmall,

    #[snafu(display("invalid magic"))]
    InvalidMagic,

    #[snafu(display("cannot read block mapping"))]
    ReadBlockMappingFailed { source: std::io::Error },
}

/// A decompressing [`Image`] adapter for PFSC-compressed files.
///
/// Each PFSC block is independently compressed, so `read_at` at any offset
/// only needs to decompress one block (or two if straddling a boundary).
/// All state is local to each call — no shared mutable state, naturally
/// thread-safe.
///
/// Created via [`PfscImage::open()`].
///
/// # Example
///
/// ```no_run
/// use orbis_pfs::image::Image;
/// use orbis_pfs::pfsc::PfscImage;
///
/// # fn example(source: impl Image) -> Result<(), Box<dyn std::error::Error>> {
/// let pfsc = PfscImage::open(source)?;
/// let pfs = orbis_pfs::open_image(pfsc)?;
/// # Ok(())
/// # }
/// ```
pub struct PfscImage<I: Image> {
    source: I,
    block_size: u32,
    original_block_size: u64,
    compressed_blocks: Vec<u64>,
    original_size: u64,
}

impl<I: Image> std::fmt::Debug for PfscImage<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PfscImage")
            .field("block_size", &self.block_size)
            .field("original_block_size", &self.original_block_size)
            .field("original_size", &self.original_size)
            .finish_non_exhaustive()
    }
}

impl<I: Image> PfscImage<I> {
    /// Opens a PFSC-compressed image from an underlying [`Image`] source.
    ///
    /// Reads the PFSC header and block offset table at construction time.
    pub fn open(source: I) -> Result<Self, OpenError> {
        // Read header.
        let mut header_buf = [0u8; size_of::<PfscHeader>()];

        source.read_exact_at(0, &mut header_buf).map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                OpenError::TooSmall
            } else {
                OpenError::IoFailed { source: e }
            }
        })?;

        let header =
            PfscHeader::read_from_bytes(&header_buf).expect("header buffer is correctly sized");

        ensure!(&header.magic == PFSC_MAGIC, InvalidMagicSnafu);

        let block_size = header.block_size.get();
        let original_block_size = header.block_size2.get();
        let block_offsets_offset = header.block_offsets.get();
        let original_size = header.data_length.get();

        // Read block offsets.
        let original_block_count = original_size / original_block_size + 1;
        let mut compressed_blocks: Vec<u64> = vec![0; original_block_count as usize];

        source
            .read_exact_at(
                block_offsets_offset,
                compressed_blocks.as_mut_slice().as_mut_bytes(),
            )
            .map_err(|e| OpenError::ReadBlockMappingFailed { source: e })?;

        Ok(Self {
            source,
            block_size,
            original_block_size,
            compressed_blocks,
            original_size,
        })
    }

    /// Returns the decompressed size of the file.
    #[must_use]
    pub fn decompressed_len(&self) -> u64 {
        self.original_size
    }

    /// Returns a reference to the underlying image source.
    pub fn source(&self) -> &I {
        &self.source
    }

    /// Returns the original (decompressed) block size in bytes.
    #[must_use]
    pub fn original_block_size(&self) -> u64 {
        self.original_block_size
    }

    /// Returns the compressed block offset table.
    ///
    /// `compressed_blocks[i]` is the byte offset within the PFSC stream where
    /// compressed block `i` starts. The compressed size of block `i` is
    /// `compressed_blocks[i + 1] - compressed_blocks[i]`.
    pub fn compressed_block_offsets(&self) -> &[u64] {
        &self.compressed_blocks
    }

    /// Decompresses a single PFSC block into `out`.
    ///
    /// `out` must be exactly `self.block_size` bytes.
    fn decompress_block(&self, num: u64, out: &mut [u8]) -> io::Result<()> {
        debug_assert_eq!(out.len(), self.block_size as usize);

        // Get compressed block range.
        let end = match self.compressed_blocks.get(num as usize + 1) {
            Some(&v) => v,
            None => return Err(io::Error::from(ErrorKind::InvalidInput)),
        };

        let offset = self.compressed_blocks[num as usize];
        let size = end - offset;

        match size.cmp(&self.original_block_size) {
            std::cmp::Ordering::Less => {
                // Read compressed data.
                let mut compressed_buf = vec![0u8; size as usize];
                self.source.read_exact_at(offset, &mut compressed_buf)?;

                // Decompress.
                let mut deflate = flate2::Decompress::new(true);

                let status = match deflate.decompress(&compressed_buf, out, FlushDecompress::Finish)
                {
                    Ok(v) => v,
                    Err(e) => return Err(io::Error::other(e)),
                };

                if status != flate2::Status::StreamEnd || deflate.total_out() as usize != out.len()
                {
                    return Err(io::Error::other(format!(
                        "invalid data on PFSC block #{}",
                        num
                    )));
                }
            }

            std::cmp::Ordering::Equal => {
                // Uncompressed block — read directly.
                self.source.read_exact_at(offset, out)?;
            }

            std::cmp::Ordering::Greater => {
                // Sparse / zero block.
                out.fill(0);
            }
        }

        Ok(())
    }
}

impl<I: Image> Image for PfscImage<I> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || offset >= self.original_size {
            return Ok(0);
        }

        let block_size = self.block_size as u64;
        let mut copied = 0usize;
        let mut pos = offset;
        let mut block_buf = vec![0u8; self.block_size as usize];

        while copied < buf.len() && pos < self.original_size {
            // Determine which PFSC block and offset within it.
            let block_index = pos / block_size;
            let offset_in_block = (pos % block_size) as usize;

            // Decompress the block.
            self.decompress_block(block_index, &mut block_buf)?;

            // Trim the last block if it extends past the original size.
            let block_end = (block_index + 1) * block_size;
            let valid_in_block = if block_end > self.original_size {
                (self.original_size - block_index * block_size) as usize
            } else {
                self.block_size as usize
            };

            // Copy the relevant portion to the output buffer.
            let available = valid_in_block - offset_in_block;
            let n = min(available, buf.len() - copied);

            buf[copied..copied + n]
                .copy_from_slice(&block_buf[offset_in_block..offset_in_block + n]);

            copied += n;
            pos += n as u64;
        }

        Ok(copied)
    }

    fn len(&self) -> u64 {
        self.original_size
    }
}

// --- Marker trait propagation for PfscImage ---

use crate::image::HasEncryption;
use aes::Aes128;
use xts_mode::Xts128;

impl<I: Image + HasEncryption> HasEncryption for PfscImage<I> {
    fn xts_cipher(&self) -> &Xts128<Aes128> {
        self.source.xts_cipher()
    }

    fn xts_encrypted_start(&self) -> usize {
        self.source.xts_encrypted_start()
    }
}

/// Marker trait: the image stack contains a PFSC compression layer.
pub trait HasPfsc: Image {
    /// Returns the original (decompressed) block size in bytes.
    fn pfsc_block_size(&self) -> u64;

    /// Returns the compressed block offset table.
    fn pfsc_block_offsets(&self) -> &[u64];
}

impl<I: Image> HasPfsc for PfscImage<I> {
    fn pfsc_block_size(&self) -> u64 {
        self.original_block_size
    }

    fn pfsc_block_offsets(&self) -> &[u64] {
        &self.compressed_blocks
    }
}

use crate::image::HasOverlay;

impl<I: Image + HasOverlay> HasOverlay for PfscImage<I> {
    fn overlay_segments(&self) -> Vec<(u64, Vec<u8>)> {
        self.source.overlay_segments()
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        self.source.write_at(offset, data)
    }
}
