//! A library for parsing and extracting PlayStation 4 PKG files.
//!
//! This crate provides functionality to parse PKG files, which are the package
//! format used by PlayStation 4 for distributing games, updates, and DLC.
//!
//! # Features
//!
//! - Parse PKG headers and metadata (content ID, type, DRM info)
//! - Iterate over and extract PKG entries
//! - Decrypt encrypted entries using the appropriate keys
//! - Access the embedded PFS image for game content
//!
//! # Example
//!
//! ```no_run
//! use orbis_pkg::Pkg;
//!
//! // Open a PKG from any byte source
//! let bytes = std::fs::read("game.pkg").unwrap();
//! let pkg = Pkg::new(bytes).unwrap();
//!
//! // Access header information
//! println!("Content ID: {}", pkg.header().content_id());
//! println!("Entry count: {}", pkg.entry_count());
//!
//! // Iterate over entries
//! for result in pkg.entries() {
//!     let (index, entry) = result.unwrap();
//!     println!("Entry {}: id=0x{:08X}", index, entry.id());
//! }
//!
//! // Access the PFS image
//! if let Some(pfs) = pkg.get_pfs_image() {
//!     // Use orbis_pfs to read the PFS image
//!     println!("PFS image size: {} bytes", pfs.data.len());
//! }
//! ```
//!
//! # References
//!
//! - [PS4 Developer Wiki - PKG files](https://www.psdevwiki.com/ps4/PKG_files)

use self::entry::{EntryId, PkgEntry};
use self::header::PkgHeader;
use self::keys::{fake_pfs_key, pkg_key3};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use sha2::Digest;
use snafu::{ResultExt, Snafu};
use std::io::Read;

use open_error::*;

pub mod entry;
pub mod header;
pub mod keys;

/// A parsed PS4 PKG file.
///
/// This struct provides read-only access to the PKG contents including
/// entries, headers, and the encrypted PFS image.
///
/// Reference: <https://www.psdevwiki.com/ps4/PKG_files>
#[must_use]
pub struct Pkg<R: AsRef<[u8]>> {
    raw: R,
    header: PkgHeader,
    entry_key3: Vec<u8>,
    ekpfs: Vec<u8>,
}

impl<R: AsRef<[u8]>> std::fmt::Debug for Pkg<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkg")
            .field("header", &self.header)
            .field("entry_count", &self.entry_count())
            .finish_non_exhaustive()
    }
}

impl<R: AsRef<[u8]>> Pkg<R> {
    /// Creates a new [`Pkg`] from raw bytes.
    ///
    /// Parses the header, entry keys, and EKPFS from the provided data.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use orbis_pkg::Pkg;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let bytes = std::fs::read("game.pkg")?;
    /// let pkg = Pkg::new(bytes)?;
    /// println!("Content ID: {}", pkg.header().content_id());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(raw: R) -> Result<Self, OpenError> {
        let header = PkgHeader::read(raw.as_ref()).context(ReadHeaderFailedSnafu)?;

        let mut pkg = Self {
            raw,
            header,
            entry_key3: Vec::new(),
            ekpfs: Vec::new(),
        };
        pkg.load_entry_key3()?;
        pkg.load_ekpfs()?;
        Ok(pkg)
    }

    /// Returns a reference to the PKG header.
    pub fn header(&self) -> &PkgHeader {
        &self.header
    }

    /// Returns the number of entries in the PKG.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.header.entry_count()
    }

    /// Returns an iterator over all entries in the PKG.
    ///
    /// Each item contains the entry index and the entry metadata.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use orbis_pkg::Pkg;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let bytes = std::fs::read("game.pkg")?;
    /// let pkg = Pkg::new(bytes)?;
    ///
    /// for result in pkg.entries() {
    ///     let (index, entry) = result?;
    ///     println!("Entry {}: id=0x{:08X}, size={}", index, entry.id(), entry.data_size());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn entries(&self) -> PkgEntries<'_> {
        PkgEntries {
            raw: self.raw.as_ref(),
            table_offset: self.header.table_offset(),
            current: 0,
            total: self.header.entry_count(),
        }
    }

    /// Gets the decrypted data for an entry.
    ///
    /// Returns the decrypted data with any padding removed.
    ///
    /// # Errors
    ///
    /// Returns [`EntryDataError::NoDecryptionKey`] if the entry is encrypted
    /// and no decryption key is available for its key index.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use orbis_pkg::Pkg;
    /// use orbis_pkg::entry::EntryId;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let bytes = std::fs::read("game.pkg")?;
    /// let pkg = Pkg::new(bytes)?;
    ///
    /// // Find and extract param.sfo
    /// if let Ok((entry, _)) = pkg.find_entry(EntryId::ParamSfo) {
    ///     let data = pkg.entry_data(&entry)?;
    ///     std::fs::write("param.sfo", &data)?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn entry_data(&self, entry: &PkgEntry) -> Result<Vec<u8>, EntryDataError> {
        // Check if we have a decryption key for encrypted entries.
        if entry.is_encrypted() && (entry.key_index() != 3 || self.entry_key3.is_empty()) {
            return Err(EntryDataError::NoDecryptionKey {
                key_index: entry.key_index(),
            });
        }

        // Get entry data offset and size.
        let offset = entry.data_offset();
        let padded_size = if entry.is_encrypted() {
            (entry.data_size() + 15) & !15 // Include padding for decryption.
        } else {
            entry.data_size()
        };

        let raw_data = self
            .raw
            .as_ref()
            .get(offset..(offset + padded_size))
            .ok_or(EntryDataError::InvalidDataOffset)?;

        // Decrypt if needed.
        if entry.is_encrypted() {
            if raw_data.len() % 16 != 0 {
                return Err(EntryDataError::MisalignedData {
                    size: raw_data.len(),
                });
            }

            let mut decrypted = self.decrypt_entry_data(entry, raw_data);
            // Truncate to actual size (remove padding).
            decrypted.truncate(entry.data_size());
            Ok(decrypted)
        } else {
            Ok(raw_data.to_vec())
        }
    }

    /// Returns the embedded PFS image and its encryption key.
    ///
    /// Returns `None` if the PFS offset/size is invalid.
    #[must_use]
    pub fn get_pfs_image(&self) -> Option<PfsImage<'_>> {
        let offset = self.header.pfs_offset();
        let size = self.header.pfs_size();
        let data = self.raw.as_ref().get(offset..(offset + size))?;
        Some(PfsImage {
            data,
            ekpfs: &self.ekpfs,
        })
    }

    /// Finds an entry by its ID.
    ///
    /// Returns the entry and its index if found.
    pub fn find_entry(&self, id: EntryId) -> Result<(PkgEntry, usize), FindEntryError> {
        self.find_entry_raw(id.as_u32())
    }

    /// Finds an entry by its raw numeric ID.
    ///
    /// This is useful when working with unknown/unsupported IDs.
    pub fn find_entry_raw(&self, id: u32) -> Result<(PkgEntry, usize), FindEntryError> {
        for num in 0..self.header.entry_count() {
            let offset = self.header.table_offset() + num * PkgEntry::RAW_SIZE;
            let raw = self
                .raw
                .as_ref()
                .get(offset..(offset + PkgEntry::RAW_SIZE))
                .ok_or(FindEntryError::InvalidOffset { num })?;

            let entry =
                PkgEntry::read(raw).map_err(|source| FindEntryError::ReadFailed { source })?;

            if entry.id() == id {
                return Ok((entry, num));
            }
        }

        Err(FindEntryError::NotFound)
    }

    fn load_ekpfs(&mut self) -> Result<(), OpenError> {
        // Locate image key entry.
        let (entry, _) = match self.find_entry(EntryId::PfsImageKey) {
            Ok(v) => v,
            Err(e) => match e {
                FindEntryError::NotFound => return Err(OpenError::PfsImageKeyNotFound),
                _ => return Err(OpenError::FindPfsImageKeyFailed { source: e }),
            },
        };

        // Get and decrypt the entry data.
        let data = self
            .entry_data(&entry)
            .context(open_error::GetPfsImageKeyFailedSnafu)?;

        // Decrypt EKPFS with fake pkg key.
        let fake_key = fake_pfs_key();
        self.ekpfs = fake_key
            .decrypt(rsa::Pkcs1v15Encrypt, &data)
            .context(DecryptEkpfsFailedSnafu)?;

        Ok(())
    }

    fn decrypt_entry_data(&self, entry: &PkgEntry, mut encrypted: &[u8]) -> Vec<u8> {
        debug_assert_eq!(encrypted.len() % 16, 0);

        // Setup decryptor.
        let (key, iv) = self.derive_entry_key3(entry);
        let mut decryptor = cbc::Decryptor::<aes::Aes128>::new(&key.into(), &iv.into());

        // Decrypt blocks.
        let mut out = Vec::with_capacity(encrypted.len());

        while !encrypted.is_empty() {
            let mut block = [0u8; 16];
            encrypted.read_exact(&mut block).unwrap();
            decryptor.decrypt_block_mut(GenericArray::from_mut_slice(&mut block));
            out.extend_from_slice(&block);
        }

        out
    }

    /// Get key and IV for `entry` using `entry_key3`.
    fn derive_entry_key3(&self, entry: &PkgEntry) -> ([u8; 16], [u8; 16]) {
        // Calculate secret.
        let mut sha256 = sha2::Sha256::new();
        sha256.update(entry.as_bytes());
        sha256.update(&self.entry_key3);
        let secret = sha256.finalize();

        // Extract key and IV.
        let (iv, key) = secret.split_at(16);
        (key.try_into().unwrap(), iv.try_into().unwrap())
    }

    fn load_entry_key3(&mut self) -> Result<(), OpenError> {
        // Locate entry keys.
        let (entry, index) = match self.find_entry(EntryId::EntryKeys) {
            Ok(v) => v,
            Err(e) => match e {
                FindEntryError::NotFound => return Err(OpenError::EntryKeyNotFound),
                _ => return Err(OpenError::FindEntryKeyFailed { source: e }),
            },
        };

        // Get raw entry data (not decrypted, as this contains the keys themselves).
        let offset = entry.data_offset();
        let size = entry.data_size();
        let mut data = self
            .raw
            .as_ref()
            .get(offset..(offset + size))
            .ok_or(OpenError::InvalidEntryOffset { num: index })?;

        // Read seed.
        let mut seed = [0u8; 32];
        if data.read_exact(&mut seed).is_err() {
            return Err(OpenError::InvalidEntryOffset { num: index });
        };

        // Read digests.
        let mut digests: [[u8; 32]; 7] = [[0u8; 32]; 7];
        digests
            .iter_mut()
            .try_for_each(|digest| data.read_exact(digest))
            .map_err(|_| OpenError::InvalidEntryOffset { num: index })?;

        // Read keys.
        let mut keys: [[u8; 256]; 7] = [[0u8; 256]; 7];
        keys.iter_mut()
            .try_for_each(|key| data.read_exact(key))
            .map_err(|_| OpenError::InvalidEntryOffset { num: index })?;

        // Decrypt key 3.
        let key3 = pkg_key3();
        self.entry_key3 = key3
            .decrypt(rsa::Pkcs1v15Encrypt, &keys[3])
            .context(DecryptEntryKeyFailedSnafu { key_index: 3usize })?;

        Ok(())
    }
}

/// The embedded PFS image and its encryption key, returned by [`Pkg::get_pfs_image()`].
#[derive(Debug)]
pub struct PfsImage<'a> {
    /// The raw PFS image bytes.
    pub data: &'a [u8],
    /// The EKPFS key needed to decrypt and open the PFS.
    pub ekpfs: &'a [u8],
}

/// Iterator over PKG entries.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct PkgEntries<'a> {
    raw: &'a [u8],
    table_offset: usize,
    current: usize,
    total: usize,
}

impl std::fmt::Debug for PkgEntries<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkgEntries")
            .field("current", &self.current)
            .field("total", &self.total)
            .finish_non_exhaustive()
    }
}

impl Iterator for PkgEntries<'_> {
    type Item = Result<(usize, PkgEntry), EntryReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.total {
            return None;
        }

        let num = self.current;
        self.current += 1;

        let offset = self.table_offset + num * PkgEntry::RAW_SIZE;
        let raw = match self.raw.get(offset..(offset + PkgEntry::RAW_SIZE)) {
            Some(v) => v,
            None => return Some(Err(EntryReadError::InvalidOffset { num })),
        };

        Some(
            PkgEntry::read(raw)
                .map_err(|source| EntryReadError::ReadFailed { source })
                .map(|entry| (num, entry)),
        )
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total - self.current;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for PkgEntries<'_> {}

#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
pub enum OpenError {
    #[snafu(display("invalid PKG header"))]
    ReadHeaderFailed { source: header::ReadError },

    #[snafu(display("no PKG entry key available"))]
    EntryKeyNotFound,

    #[snafu(display("failed to find entry key"))]
    FindEntryKeyFailed { source: FindEntryError },

    #[snafu(display("entry #{num} has invalid data offset"))]
    InvalidEntryOffset { num: usize },

    #[snafu(display("cannot decrypt entry key #{key_index}"))]
    DecryptEntryKeyFailed {
        key_index: usize,
        source: rsa::errors::Error,
    },

    #[snafu(display("no PFS image key in the PKG"))]
    PfsImageKeyNotFound,

    #[snafu(display("failed to get PFS image key"))]
    GetPfsImageKeyFailed { source: EntryDataError },

    #[snafu(display("failed to find PFS image key"))]
    FindPfsImageKeyFailed { source: FindEntryError },

    #[snafu(display("cannot decrypt EKPFS"))]
    DecryptEkpfsFailed { source: rsa::errors::Error },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
pub enum FindEntryError {
    #[snafu(display("failed to read entry"))]
    ReadFailed { source: entry::EntryError },

    #[snafu(display("entry #{num} has invalid offset"))]
    InvalidOffset { num: usize },

    #[snafu(display("the specified entry was not found"))]
    NotFound,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
pub enum EntryReadError {
    #[snafu(display("entry #{num} has invalid offset"))]
    InvalidOffset { num: usize },

    #[snafu(display("failed to read entry"))]
    ReadFailed { source: entry::EntryError },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
pub enum EntryDataError {
    #[snafu(display("no decryption key available for key index {key_index}"))]
    NoDecryptionKey { key_index: usize },

    #[snafu(display("entry has invalid data offset"))]
    InvalidDataOffset,

    #[snafu(display(
        "encrypted entry data is not block-aligned (size {size} is not a multiple of 16)"
    ))]
    MisalignedData { size: usize },
}
