use crate::Pfs;
use crate::image::Image;
use crate::inode::Inode;
use std::cmp::min;
use std::io::{self, Error, Read, Seek, SeekFrom};
use std::sync::Arc;

/// Represents a file in the PFS.
///
/// Use [`read_at()`](Self::read_at) for positional reads (thread-safe, `&self`),
/// or [`as_slice()`](Self::as_slice) for zero-copy access when available.
///
/// Files may be compressed, in which case you should use
/// [`pfsc::PfscImage`][crate::pfsc::PfscImage] as an [`Image`] adapter.
#[must_use]
pub struct File<'a, I: Image> {
    pfs: Arc<Pfs<'a, I>>,
    inode: usize,
}

impl<'a, I: Image> std::fmt::Debug for File<'a, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("File")
            .field("inode", &self.inode)
            .field("len", &self.len())
            .field("mode", &self.mode())
            .finish_non_exhaustive()
    }
}

impl<'a, I: Image> File<'a, I> {
    pub(crate) fn new(pfs: Arc<Pfs<'a, I>>, inode: usize) -> Self {
        Self { pfs, inode }
    }

    /// Returns the inode index for this file within the PFS.
    #[must_use]
    pub fn inode_index(&self) -> usize {
        self.inode
    }

    #[must_use]
    pub fn mode(&self) -> u16 {
        self.inode_ref().mode()
    }

    #[must_use]
    pub fn flags(&self) -> u32 {
        self.inode_ref().flags().value()
    }

    #[must_use]
    pub fn len(&self) -> u64 {
        self.inode_ref().size()
    }

    #[must_use]
    pub fn compressed_len(&self) -> u64 {
        self.inode_ref().compressed_len()
    }

    /// Returns the last access time as seconds since the Unix epoch.
    #[must_use]
    pub fn atime(&self) -> u64 {
        self.inode_ref().atime()
    }

    /// Returns the last modification time as seconds since the Unix epoch.
    #[must_use]
    pub fn mtime(&self) -> u64 {
        self.inode_ref().mtime()
    }

    /// Returns the last metadata change time as seconds since the Unix epoch.
    #[must_use]
    pub fn ctime(&self) -> u64 {
        self.inode_ref().ctime()
    }

    /// Returns the creation time as seconds since the Unix epoch.
    #[must_use]
    pub fn birthtime(&self) -> u64 {
        self.inode_ref().birthtime()
    }

    /// Returns the sub-second nanosecond component of [`mtime()`](Self::mtime).
    #[must_use]
    pub fn mtimensec(&self) -> u32 {
        self.inode_ref().mtimensec()
    }

    /// Returns the sub-second nanosecond component of [`atime()`](Self::atime).
    #[must_use]
    pub fn atimensec(&self) -> u32 {
        self.inode_ref().atimensec()
    }

    /// Returns the sub-second nanosecond component of [`ctime()`](Self::ctime).
    #[must_use]
    pub fn ctimensec(&self) -> u32 {
        self.inode_ref().ctimensec()
    }

    /// Returns the sub-second nanosecond component of [`birthtime()`](Self::birthtime).
    #[must_use]
    pub fn birthnsec(&self) -> u32 {
        self.inode_ref().birthnsec()
    }

    #[must_use]
    pub fn uid(&self) -> u32 {
        self.inode_ref().uid()
    }

    #[must_use]
    pub fn gid(&self) -> u32 {
        self.inode_ref().gid()
    }

    #[must_use]
    pub fn is_compressed(&self) -> bool {
        self.inode_ref().flags().is_compressed()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the file contents as a borrowed slice without a copy.
    ///
    /// This returns `Some` only when **all** of the following are true:
    /// - The PFS was opened via [`open_slice()`][crate::open_slice] with an unencrypted image
    /// - The file is not compressed
    /// - The file's blocks are laid out contiguously in the image
    ///
    /// For compressed files, use [`pfsc::PfscImage`][crate::pfsc::PfscImage] instead.
    /// When this returns `None`, use [`read_at()`](Self::read_at) as a fallback.
    #[must_use]
    pub fn as_slice(&self) -> Option<&'a [u8]> {
        let data = self.pfs.data?;

        if self.is_compressed() {
            return None;
        }

        let inode = self.inode_ref();

        if inode.size() == 0 {
            return Some(&[]);
        }

        let (start_block, _) = inode.contiguous_blocks()?;
        let block_size = self.pfs.block_size as u64;

        let start = (start_block as u64) * block_size;
        let end = start + inode.size();

        data.get(start as usize..end as usize)
    }

    /// Reads file data at the given offset without modifying any cursor.
    ///
    /// This is the primary read method. It takes `&self` (not `&mut self`)
    /// and requires no synchronization, making it safe to call from multiple
    /// threads concurrently.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        pfs_read_at(&self.pfs, self.inode, offset, buf)
    }

    /// Creates a [`FileReader`] that implements [`Read`] and [`Seek`].
    ///
    /// This is useful when you need to pass a PFS file to APIs that expect
    /// standard I/O traits (e.g. `io::copy`, decompressors, parsers).
    ///
    /// Each reader maintains its own cursor position. Multiple readers can
    /// exist concurrently for the same file.
    #[must_use]
    pub fn reader(&self) -> FileReader<'a, I> {
        FileReader {
            file: self.clone(),
            pos: 0,
        }
    }

    /// Converts this file handle into a [`PfsFileImage`] for use as an
    /// [`Image`] source (e.g. to open a nested PFS or wrap in
    /// [`PfscImage`][crate::pfsc::PfscImage]).
    pub fn into_image(self) -> PfsFileImage<'a, I> {
        PfsFileImage {
            pfs: self.pfs,
            inode: self.inode,
        }
    }

    fn inode_ref(&self) -> &Inode {
        self.pfs.inode(self.inode)
    }
}

impl<'a, I: Image> Clone for File<'a, I> {
    fn clone(&self) -> Self {
        Self {
            pfs: self.pfs.clone(),
            inode: self.inode,
        }
    }
}

/// A cursor-based reader for a PFS [`File`], implementing [`Read`] and [`Seek`].
///
/// Created via [`File::reader()`].
pub struct FileReader<'a, I: Image> {
    file: File<'a, I>,
    pos: u64,
}

impl<'a, I: Image> std::fmt::Debug for FileReader<'a, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileReader")
            .field("file", &self.file)
            .field("pos", &self.pos)
            .finish()
    }
}

impl<I: Image> Read for FileReader<'_, I> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read_at(self.pos, buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<I: Image> Seek for FileReader<'_, I> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let file_len = self.file.len();

        let new_pos = match pos {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::End(offset) => file_len as i64 + offset,
            SeekFrom::Current(offset) => self.pos as i64 + offset,
        };

        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek to a negative position",
            ));
        }

        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

/// A file within a PFS, exposed as an [`Image`] for chaining.
///
/// This adapter maps logical file offsets through the inode's precomputed block
/// map to physical offsets in the underlying PFS image. It is used to open
/// nested PFS images (e.g. `pfs_image.dat` inside an outer PFS), optionally
/// wrapped in [`PfscImage`][crate::pfsc::PfscImage] for decompression.
///
/// The type parameter `I` preserves the outer PFS's image type, enabling
/// access to its internals (e.g. encryption keys) through marker traits.
///
/// Created via [`File::into_image()`].
#[derive(Clone)]
pub struct PfsFileImage<'a, I: Image> {
    pfs: Arc<Pfs<'a, I>>,
    inode: usize,
}

impl<'a, I: Image> PfsFileImage<'a, I> {
    /// Returns a reference to the outer PFS that owns this file.
    pub fn pfs(&self) -> &Arc<Pfs<'a, I>> {
        &self.pfs
    }

    /// Returns the inode index of this file within the outer PFS.
    pub fn inode_index(&self) -> usize {
        self.inode
    }
}

impl<'a, I: Image> std::fmt::Debug for PfsFileImage<'a, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PfsFileImage")
            .field("inode", &self.inode)
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl<I: Image> Image for PfsFileImage<'_, I> {
    fn read_at(&self, offset: u64, output_buf: &mut [u8]) -> std::io::Result<usize> {
        pfs_read_at(&self.pfs, self.inode, offset, output_buf)
    }

    fn len(&self) -> u64 {
        self.pfs.inode(self.inode).size()
    }
}

// --- Marker trait propagation for PfsFileImage ---

use crate::image::HasEncryption;

impl<I: Image + HasEncryption> HasEncryption for PfsFileImage<'_, I> {
    fn xts_cipher(&self) -> &xts_mode::Xts128<aes::Aes128> {
        self.pfs.image().xts_cipher()
    }

    fn xts_encrypted_start(&self) -> usize {
        self.pfs.image().xts_encrypted_start()
    }
}

fn pfs_read_at<I: Image>(
    pfs: &Pfs<'_, I>,
    inode: usize,
    offset: u64,
    buf: &mut [u8],
) -> io::Result<usize> {
    let file_size = pfs.inode(inode).size();

    if buf.is_empty() || offset >= file_size {
        return Ok(0);
    }

    let block_map = pfs.block_map(inode);
    let block_size = pfs.block_size as u64;
    let image = pfs.image();
    let mut copied = 0usize;
    let mut pos = offset;

    loop {
        let block_index = pos / block_size;
        let offset_in_block = pos % block_size;

        let block_num = match block_map.get(block_index as usize) {
            Some(&v) => v,
            None => {
                return Err(Error::other(format!(
                    "block #{} is not available",
                    block_index
                )));
            }
        };

        let block_end = (block_index + 1) * block_size;
        let remaining_in_block = (min(block_end, file_size) - pos) as usize;
        let to_read = min(remaining_in_block, buf.len() - copied);

        let phys_offset = (block_num as u64) * block_size + offset_in_block;

        image.read_exact_at(phys_offset, &mut buf[copied..copied + to_read])?;

        copied += to_read;
        pos += to_read as u64;

        if copied == buf.len() || pos >= file_size {
            break Ok(copied);
        }
    }
}
