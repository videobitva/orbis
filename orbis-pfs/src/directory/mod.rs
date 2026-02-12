use snafu::{OptionExt, ResultExt, ensure};

use self::dirent::Dirent;
use crate::Pfs;
use crate::file::File;
use crate::image::Image;
use crate::inode::Inode;
use std::collections::BTreeMap;
use std::sync::Arc;

pub mod dirent;

/// Errors of [`Directory::open()`].
#[derive(Debug, snafu::Snafu)]
#[non_exhaustive]
pub enum OpenError {
    #[snafu(display("inode #{inode} is not valid"))]
    InvalidInode { inode: usize },

    #[snafu(display("cannot read block #{block}"))]
    ReadBlock { block: u32, source: std::io::Error },

    #[snafu(display("cannot read directory entry"))]
    ReadDirEntry { source: dirent::ReadError },

    #[snafu(display("dirent #{dirent} in block #{block} has invalid size"))]
    DirentInvalidSize { block: u32, dirent: usize },

    #[snafu(display("dirent #{dirent} in block #{block} has unknown type"))]
    DirentUnknownType { block: u32, dirent: usize },
}

/// Represents a directory in the PFS.
///
/// Use [`open()`][Self::open] to read the directory contents.
#[derive(Clone)]
#[must_use]
pub struct Directory<'a, I: Image> {
    pfs: Arc<Pfs<'a, I>>,
    inode: usize,
}

impl<'a, I: Image> std::fmt::Debug for Directory<'a, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Directory")
            .field("inode", &self.inode)
            .field("mode", &self.mode())
            .finish_non_exhaustive()
    }
}

impl<'a, I: Image> Directory<'a, I> {
    pub(super) fn new(pfs: Arc<Pfs<'a, I>>, inode: usize) -> Self {
        Self { pfs, inode }
    }

    #[must_use]
    pub fn mode(&self) -> u16 {
        self.inode_ref().mode()
    }

    #[must_use]
    pub fn flags(&self) -> u32 {
        self.inode_ref().flags().value()
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

    /// Opens this directory and reads its entries.
    ///
    /// Returns a collection of directory entries (files and subdirectories).
    pub fn open(&self) -> Result<DirEntries<'a, I>, OpenError> {
        let blocks = self.pfs.block_map(self.inode);
        let block_size = self.pfs.block_size;
        let img = self.pfs.image();

        // Read all dirents.
        let mut items: BTreeMap<Vec<u8>, DirEntry<'a, I>> = BTreeMap::new();
        let mut block_data = vec![0; block_size as usize];

        for &block_num in blocks {
            // Read block data via positional read.
            let offset = (block_num as u64) * (block_size as u64);

            img.read_exact_at(offset, &mut block_data)
                .context(ReadBlockSnafu { block: block_num })?;

            // Read dirents in the block.
            let mut next = block_data.as_slice();

            for num in 0_usize.. {
                // Read dirent.
                let dirent = match Dirent::read(&mut next) {
                    Ok(v) => v,
                    Err(dirent::ReadError::TooSmall | dirent::ReadError::EndOfEntry) => {
                        break;
                    }
                    err => err.context(ReadDirEntrySnafu)?,
                };

                // Skip remaining padding.
                next = next
                    .get(dirent.padding_size()..)
                    .context(DirentInvalidSizeSnafu {
                        block: block_num,
                        dirent: num,
                    })?;

                // Check if inode valid.
                let inode = dirent.inode();
                ensure!(inode < self.pfs.inode_count(), InvalidInodeSnafu { inode });

                // Construct object.
                let entry = match dirent.ty() {
                    Dirent::FILE => DirEntry::File(File::new(self.pfs.clone(), inode)),
                    Dirent::DIRECTORY => {
                        DirEntry::Directory(Directory::new(self.pfs.clone(), inode))
                    }
                    Dirent::SELF | Dirent::PARENT => continue,
                    _ => {
                        return Err(DirentUnknownTypeSnafu {
                            block: block_num,
                            dirent: num,
                        }
                        .build());
                    }
                };

                items.insert(dirent.name().to_vec(), entry);
            }
        }

        Ok(DirEntries { items })
    }

    fn inode_ref(&self) -> &Inode {
        self.pfs.inode(self.inode)
    }
}

/// Represents a collection of entries in a directory.
///
/// This type provides access to the files and subdirectories within a directory.
/// It can be iterated over or queried by name.
#[derive(Debug)]
#[must_use]
pub struct DirEntries<'a, I: Image> {
    items: BTreeMap<Vec<u8>, DirEntry<'a, I>>,
}

impl<'a, I: Image> DirEntries<'a, I> {
    /// Returns the number of entries in the directory.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns `true` if the directory is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns a reference to the entry with the given name.
    #[must_use]
    pub fn get(&self, name: &[u8]) -> Option<&DirEntry<'a, I>> {
        self.items.get(name)
    }

    /// Removes and returns the entry with the given name.
    pub fn remove(&mut self, name: &[u8]) -> Option<DirEntry<'a, I>> {
        self.items.remove(name)
    }

    /// Returns an iterator over the entries.
    pub fn iter(&self) -> DirEntriesIter<'_, 'a, I> {
        DirEntriesIter {
            inner: self.items.iter(),
        }
    }

    /// Returns an iterator over the entry names.
    pub fn names(&self) -> impl Iterator<Item = &[u8]> {
        self.items.keys().map(|k| k.as_slice())
    }
}

impl<'a, I: Image> IntoIterator for DirEntries<'a, I> {
    type Item = (Vec<u8>, DirEntry<'a, I>);
    type IntoIter = DirEntriesOwnedIter<'a, I>;

    fn into_iter(self) -> Self::IntoIter {
        DirEntriesOwnedIter {
            inner: self.items.into_iter(),
        }
    }
}

impl<'b, 'a, I: Image> IntoIterator for &'b DirEntries<'a, I> {
    type Item = (&'b [u8], &'b DirEntry<'a, I>);
    type IntoIter = DirEntriesIter<'b, 'a, I>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// An iterator over directory entries by reference.
#[derive(Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct DirEntriesIter<'b, 'a, I: Image> {
    inner: std::collections::btree_map::Iter<'b, Vec<u8>, DirEntry<'a, I>>,
}

impl<'b, 'a, I: Image> Iterator for DirEntriesIter<'b, 'a, I> {
    type Item = (&'b [u8], &'b DirEntry<'a, I>);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, v)| (k.as_slice(), v))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<I: Image> ExactSizeIterator for DirEntriesIter<'_, '_, I> {}

/// An owning iterator over directory entries.
#[derive(Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct DirEntriesOwnedIter<'a, I: Image> {
    inner: std::collections::btree_map::IntoIter<Vec<u8>, DirEntry<'a, I>>,
}

impl<'a, I: Image> Iterator for DirEntriesOwnedIter<'a, I> {
    type Item = (Vec<u8>, DirEntry<'a, I>);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<I: Image> ExactSizeIterator for DirEntriesOwnedIter<'_, I> {}

/// Represents an entry in a directory (either a file or subdirectory).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DirEntry<'a, I: Image> {
    /// A subdirectory.
    Directory(Directory<'a, I>),
    /// A file.
    File(File<'a, I>),
}
