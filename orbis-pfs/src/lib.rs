//! A library for reading PlayStation 4 PFS (PlayStation File System) images.
//!
//! This crate provides functionality to parse and read files from PFS images,
//! which are used by the PlayStation 4 to store game data and other content.
//!
//! # Features
//!
//! - Parse PFS image headers and metadata
//! - Read files and directories from PFS images
//! - Support for both encrypted and unencrypted PFS images
//! - Support for compressed files (PFSC format)
//! - Thread-safe: all read operations use positional I/O (`read_at`) —
//!   no shared mutable cursor, no locks in the read path
//!
//! # Example
//!
//! ```no_run
//! // Open a PFS image from a byte slice (e.g. memory-mapped file)
//! let data = std::fs::read("image.pfs").unwrap();
//! let pfs = orbis_pfs::open_slice(&data, None).unwrap();
//!
//! // Access the root directory
//! let root = pfs.root();
//! ```
//!
//! # References
//!
//! - [PS4 Developer Wiki - PFS](https://www.psdevwiki.com/ps4/PFS)

use crate::header::Mode;

use self::directory::Directory;
use self::header::PfsHeader;
use self::inode::Inode;
use aes::Aes128;
use aes::cipher::KeyInit;
use snafu::{OptionExt, ResultExt, Snafu, ensure};
use std::sync::Arc;
use xts_mode::Xts128;

pub mod directory;
pub mod file;
pub mod header;
pub mod image;
pub mod inode;
pub mod pfsc;

/// Shared errors for PFS open operations.
///
/// These errors can occur in both [`open_slice()`] and [`open_image()`] during
/// the common phase: validating the header, reading inodes, and precomputing
/// block maps.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum OpenError {
    #[snafu(display("invalid block size"))]
    InvalidBlockSize,

    #[snafu(display("cannot parse inode"))]
    ParseInodeFailed { source: inode::FromRawError },

    #[snafu(display("cannot read block #{block}"))]
    ReadBlockFailed { block: u32, source: std::io::Error },

    #[snafu(display("invalid super-root"))]
    InvalidSuperRoot,

    #[snafu(display("cannot load block map for inode #{inode}"))]
    LoadBlockMapFailed {
        inode: usize,
        source: inode::LoadBlocksError,
    },
}

/// Errors for [`open_slice()`].
#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
pub enum OpenSliceError {
    #[snafu(display("cannot parse header"))]
    ReadHeaderFailed { source: header::ReadError },

    #[snafu(display("block size too small for encryption"))]
    EncryptionBlockSizeTooSmall,

    #[snafu(display("encryption required but no EKPFS is provided"))]
    EmptyEkpfs,

    #[snafu(transparent)]
    Open { source: OpenError },
}

/// Errors for [`open_image()`].
#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
pub enum OpenImageError {
    #[snafu(display("cannot read header from image"))]
    ReadHeaderIoFailed { source: std::io::Error },

    #[snafu(display("cannot parse header"))]
    ReadHeaderFailed { source: header::ReadError },

    #[snafu(display("unsupported mode: {mode}"))]
    UnsupportedMode { mode: Mode },

    #[snafu(transparent)]
    Open { source: OpenError },
}

/// Represents a loaded PFS.
///
/// This type is `Send + Sync` and can be shared across threads via [`Arc`].
/// All read operations use positional I/O, so concurrent reads from multiple
/// threads do not require synchronization.
#[must_use]
pub struct Pfs<'a> {
    image: Box<dyn image::Image + 'a>,
    inodes: Vec<Inode>,
    /// Precomputed block maps: `block_maps[inode_index]` gives the
    /// logical-block -> physical-block mapping for that inode.
    block_maps: Vec<Vec<u32>>,
    root: usize,
    block_size: u32,
    /// Backing data for unencrypted, slice-backed images (from [`open_slice()`]).
    /// Enables zero-copy file access via [`file::File::as_slice()`].
    data: Option<&'a [u8]>,
}

// SAFETY: All fields are Send + Sync:
// - Box<dyn Image + 'a>: Image requires Send + Sync
// - Vec<Inode>: Inode contains only Copy/primitive types
// - Vec<Vec<u32>>, usize, u32: trivially Send + Sync
// - Option<&'a [u8]>: &[u8] is Send + Sync
unsafe impl Send for Pfs<'_> {}
unsafe impl Sync for Pfs<'_> {}

impl<'a> std::fmt::Debug for Pfs<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pfs")
            .field("inode_count", &self.inodes.len())
            .field("root", &self.root)
            .field("block_size", &self.block_size)
            .field("slice_backed", &self.data.is_some())
            .finish_non_exhaustive()
    }
}

impl<'a> Pfs<'a> {
    /// Returns the number of inodes in this PFS.
    ///
    /// This represents the total number of files and directories in the filesystem.
    #[must_use]
    pub fn inode_count(&self) -> usize {
        self.inodes.len()
    }

    /// Returns the root directory of this PFS.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let data = std::fs::read("image.pfs")?;
    /// let pfs = orbis_pfs::open_slice(&data, None)?;
    ///
    /// // Get the root directory
    /// let root = pfs.root();
    ///
    /// // Open and iterate over entries
    /// for (name, entry) in root.open()? {
    ///     println!("Entry: {:?}", String::from_utf8_lossy(&name));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn root(self: &Arc<Self>) -> Directory<'a> {
        Directory::new(self.clone(), self.root)
    }

    /// Returns the block size used by this PFS.
    #[must_use]
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    // --- Internal accessors for File / Directory / PfsFileImage ---

    pub(crate) fn image(&self) -> &dyn image::Image {
        &*self.image
    }

    pub(crate) fn inode(&self, index: usize) -> &Inode {
        &self.inodes[index]
    }

    pub(crate) fn block_map(&self, inode: usize) -> &[u32] {
        &self.block_maps[inode]
    }
}

/// Opens a PFS image for reading from a byte slice.
///
/// This is the primary entry point when the image data is already in memory.
///
/// For unencrypted images, this avoids intermediate buffer allocations during
/// header and inode parsing by reading directly from the slice, and enables
/// zero-copy file access via [`file::File::as_slice()`].
///
/// # Arguments
///
/// * `data` - The PFS image data as a byte slice
/// * `ekpfs` - The EKPFS key for encrypted images, or `None` for unencrypted images
///
/// # Returns
///
/// Returns a thread-safe, reference-counted [`Pfs`] handle on success.
///
/// # Errors
///
/// Returns an [`OpenSliceError`] if:
/// - The image header is invalid
/// - The image is encrypted but no key is provided
/// - The block structure is invalid
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let data = std::fs::read("image.pfs")?;
/// let pfs = orbis_pfs::open_slice(&data, None)?;
/// println!("Opened PFS with {} inodes", pfs.inode_count());
/// # Ok(())
/// # }
/// ```
pub fn open_slice<'a>(
    data: &'a [u8],
    ekpfs: Option<&[u8]>,
) -> Result<Arc<Pfs<'a>>, OpenSliceError> {
    // Parse header directly from the slice.
    let header = PfsHeader::from_bytes(data).context(open_slice_error::ReadHeaderFailedSnafu)?;

    // Build the appropriate Image backend and determine zero-copy backing data.
    let (image, backing_data): (Box<dyn image::Image + 'a>, Option<&'a [u8]>) =
        if header.mode().is_encrypted() {
            ensure!(
                (header.block_size() as usize) >= image::XTS_BLOCK_SIZE,
                open_slice_error::EncryptionBlockSizeTooSmallSnafu
            );

            let ekpfs_bytes = ekpfs.context(open_slice_error::EmptyEkpfsSnafu)?;

            let key_seed = header.key_seed();
            let (data_key, tweak_key) = image::get_xts_keys(ekpfs_bytes, key_seed);
            let cipher_1 = Aes128::new((&data_key).into());
            let cipher_2 = Aes128::new((&tweak_key).into());

            let enc = image::EncryptedSlice::new(
                data,
                Xts128::<Aes128>::new(cipher_1, cipher_2),
                (header.block_size() as usize) / image::XTS_BLOCK_SIZE,
            );

            (Box::new(enc), None)
        } else {
            (Box::new(image::UnencryptedSlice::new(data)), Some(data))
        };

    Ok(open_inner(image, &header, backing_data)?)
}

/// Opens a PFS image for reading from any [`Image`](image::Image) implementation.
///
/// This is used when the PFS image is behind a transformation layer (e.g.
/// a file within another PFS, optionally PFSC-compressed). The image is read
/// entirely through [`Image::read_at()`](image::Image::read_at).
///
/// # Arguments
///
/// * `image` - An [`Image`](image::Image) providing positional read access to the PFS data
///
/// # Returns
///
/// Returns a thread-safe, reference-counted [`Pfs`] handle on success.
///
/// # Errors
///
/// Returns an [`OpenImageError`] if the image header or block structure is invalid.
///
/// # Example
///
/// ```no_run
/// use orbis_pfs::image::Image;
///
/// # fn open_inner(image: impl Image) -> Result<(), Box<dyn std::error::Error>> {
/// let pfs = orbis_pfs::open_image(image)?;
/// println!("Opened PFS with {} inodes", pfs.inode_count());
/// # Ok(())
/// # }
/// ```
pub fn open_image<'a>(image: impl image::Image + 'a) -> Result<Arc<Pfs<'a>>, OpenImageError> {
    // Read header via positional read.
    let mut header_buf = [0u8; header::HEADER_SIZE];

    image
        .read_exact_at(0, &mut header_buf)
        .context(open_image_error::ReadHeaderIoFailedSnafu)?;

    let header =
        PfsHeader::from_bytes(&header_buf).context(open_image_error::ReadHeaderFailedSnafu)?;

    ensure!(
        !header.mode().is_encrypted(),
        open_image_error::UnsupportedModeSnafu {
            mode: header.mode()
        }
    );

    Ok(open_inner(Box::new(image), &header, None)?)
}

/// Shared implementation for [`open_slice()`] and [`open_image()`].
///
/// Validates the header fields, reads inodes, precomputes block maps, and
/// constructs the [`Pfs`].
fn open_inner<'a>(
    image: Box<dyn image::Image + 'a>,
    header: &PfsHeader,
    data: Option<&'a [u8]>,
) -> Result<Arc<Pfs<'a>>, OpenError> {
    let mode = header.mode();
    let block_size = header.block_size();
    let inode_count = header.inode_count();
    let inode_block_count = header.inode_block_count();
    let super_root = header.super_root_inode();

    ensure!(
        block_size > 0 && block_size.is_power_of_two(),
        InvalidBlockSizeSnafu
    );

    // Read and parse all inodes.
    let mut inodes: Vec<Inode> = Vec::with_capacity(inode_count);
    let mut block_buf = vec![0; block_size as usize];

    for block_num in 0..inode_block_count {
        let offset = (block_size as u64) + (block_num as u64) * (block_size as u64);

        image
            .read_exact_at(offset, &mut block_buf)
            .context(ReadBlockFailedSnafu { block: block_num })?;

        if parse_inodes_from_block(&block_buf, mode, &mut inodes, inode_count)? {
            break;
        }
    }

    ensure!(super_root < inodes.len(), InvalidSuperRootSnafu);

    // Precompute block maps for all inodes.
    let block_maps = precompute_block_maps(&inodes, image.as_ref(), block_size)?;

    Ok(Arc::new(Pfs {
        image,
        inodes,
        block_maps,
        root: super_root,
        block_size,
        data,
    }))
}

/// Precomputes block maps for all inodes.
fn precompute_block_maps(
    inodes: &[Inode],
    image: &dyn image::Image,
    block_size: u32,
) -> Result<Vec<Vec<u32>>, OpenError> {
    let mut maps = Vec::with_capacity(inodes.len());

    for (i, inode) in inodes.iter().enumerate() {
        let block_map = inode
            .load_block_map(image, block_size)
            .context(LoadBlockMapFailedSnafu { inode: i })?;
        maps.push(block_map);
    }

    Ok(maps)
}

/// Parses inodes from a single block of data.
///
/// Returns `true` if all expected inodes have been parsed, `false` if more blocks are
/// needed (the current block was exhausted before reaching `inode_count`).
fn parse_inodes_from_block(
    block_data: &[u8],
    mode: Mode,
    inodes: &mut Vec<Inode>,
    inode_count: usize,
) -> Result<bool, OpenError> {
    let reader = if mode.is_signed() {
        Inode::from_raw32_signed
    } else {
        Inode::from_raw32_unsigned
    };

    let mut src = block_data;

    while inodes.len() < inode_count {
        let inode = match reader(inodes.len(), &mut src) {
            Ok(v) => v,
            Err(inode::FromRawError::TooSmall) => {
                return Ok(false);
            }
            err => err.context(ParseInodeFailedSnafu)?,
        };

        inodes.push(inode);
    }

    Ok(true)
}
