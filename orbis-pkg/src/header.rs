use std::fmt;

use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned,
    byteorder::big_endian::{U16, U32, U64},
};

/// Errors when reading a PKG header.
#[derive(Debug, snafu::Snafu)]
#[non_exhaustive]
pub enum ReadError {
    #[snafu(display("PKG file is too small"))]
    TooSmall,
    #[snafu(display("invalid PKG magic"))]
    InvalidMagic,

    #[snafu(display("invalid source bytes"))]
    InvalidSourceBytes,
}

type Result<T, E = ReadError> = std::result::Result<T, E>;

const PKG_MAGIC: u32 = 0x7F434E54;

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct PkgHeaderRaw {
    // Main header fields
    pub pkg_magic: U32,            // 0x000 - 0x7F434E54
    pub pkg_type: U32,             // 0x004
    pub pkg_0x008: U32,            // 0x008 - unknown field
    pub pkg_file_count: U32,       // 0x00C
    pub pkg_entry_count: U32,      // 0x010
    pub pkg_sc_entry_count: U16,   // 0x014
    pub pkg_entry_count_2: U16,    // 0x016 - same as pkg_entry_count
    pub pkg_table_offset: U32,     // 0x018 - file table offset
    pub pkg_entry_data_size: U32,  // 0x01C
    pub pkg_body_offset: U64,      // 0x020 - offset of PKG entries
    pub pkg_body_size: U64,        // 0x028 - length of all PKG entries
    pub pkg_content_offset: U64,   // 0x030
    pub pkg_content_size: U64,     // 0x038
    pub pkg_content_id: ContentId, // 0x040 - packages' content ID (36 bytes)
    pub pkg_padding: [u8; 0xC],    // 0x064 - padding
    pub pkg_drm_type: U32,         // 0x070 - DRM type
    pub pkg_content_type: U32,     // 0x074 - Content type
    pub pkg_content_flags: U32,    // 0x078 - Content flags
    pub pkg_promote_size: U32,     // 0x07C
    pub pkg_version_date: U32,     // 0x080
    pub pkg_version_hash: U32,     // 0x084
    pub pkg_0x088: U32,            // 0x088
    pub pkg_0x08c: U32,            // 0x08C
    pub pkg_0x090: U32,            // 0x090
    pub pkg_0x094: U32,            // 0x094
    pub pkg_iro_tag: U32,          // 0x098
    pub pkg_drm_type_version: U32, // 0x09C

    // Padding between header and digest table (0x0A0 - 0x100)
    pub padding_0x0a0: [u8; 0x60],

    // Digest table (0x100 - 0x180)
    pub digest_table: DigestTable,

    // Padding between digest table and PFS info (0x180 - 0x404)
    pub padding_0x180: [u8; 0x284],

    // PFS image info
    pub pfs_image_count: U32,          // 0x404 - count of PFS images
    pub pfs_image_flags: U64,          // 0x408 - PFS flags
    pub pfs_image_offset: U64,         // 0x410 - offset to start of external PFS image
    pub pfs_image_size: U64,           // 0x418 - size of external PFS image
    pub mount_image_offset: U64,       // 0x420
    pub mount_image_size: U64,         // 0x428
    pub pkg_size: U64,                 // 0x430
    pub pfs_signed_size: U32,          // 0x438
    pub pfs_cache_size: U32,           // 0x43C
    pub pfs_image_digest: [u8; 0x20],  // 0x440
    pub pfs_signed_digest: [u8; 0x20], // 0x460
    pub pfs_split_size_nth_0: U64,     // 0x480
    pub pfs_split_size_nth_1: U64,     // 0x488

    // Padding between PFS info and final digest (0x490 - 0xFE0)
    pub padding_0x490: [u8; 0xB50],

    // Final digest
    pub pkg_digest: [u8; 0x20], // 0xFE0
                                // 0x1000 - end of header
}

/// Content ID structure (36 bytes).
///
/// Format: `<service_id><region>-<title_id>_<version>-<label>`
/// Example: `UP0102-CUSA03173_00-PSYCHONAUTS1PS40`
#[derive(
    Clone,
    Copy,
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
pub struct ContentId {
    /// Service ID (2 bytes): "UP", "EP", "JP", "HP", "IP", etc.
    service_id: [u8; 2],
    /// Publisher/region code (4 bytes): e.g., "0102"
    publisher_code: [u8; 4],
    /// Separator (1 byte): "-"
    _sep1: u8,
    /// Title ID (9 bytes): e.g., "CUSA03173", "PPSA01234"
    title_id: [u8; 9],
    /// Separator (1 byte): "_"
    _sep2: u8,
    /// Content version (2 bytes): e.g., "00"
    version: [u8; 2],
    /// Separator (1 byte): "-"
    _sep3: u8,
    /// Content label (16 bytes): e.g., "PSYCHONAUTS1PS40"
    label: [u8; 16],
}

impl ContentId {
    /// Returns the service ID (e.g., "UP", "EP", "JP").
    #[must_use]
    pub fn service_id(&self) -> &str {
        std::str::from_utf8(&self.service_id).unwrap_or("")
    }

    /// Returns the publisher/region code (e.g., "0102").
    #[must_use]
    pub fn publisher_code(&self) -> &str {
        std::str::from_utf8(&self.publisher_code).unwrap_or("")
    }

    /// Returns the title ID (e.g., "CUSA03173").
    #[must_use]
    pub fn title_id(&self) -> &str {
        let bytes = &self.title_id;
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..len]).unwrap_or("")
    }

    /// Returns the content version (e.g., "00").
    #[must_use]
    pub fn version(&self) -> &str {
        std::str::from_utf8(&self.version).unwrap_or("")
    }

    /// Returns the content label (e.g., "PSYCHONAUTS1PS40").
    #[must_use]
    pub fn label(&self) -> &str {
        let bytes = &self.label;
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..len]).unwrap_or("")
    }

    /// Returns the full content ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        let bytes = self.as_bytes();
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..len]).unwrap_or("<invalid>")
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl fmt::Debug for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentId")
            .field("service_id", &self.service_id())
            .field("publisher_code", &self.publisher_code())
            .field("title_id", &self.title_id())
            .field("version", &self.version())
            .field("label", &self.label())
            .finish()
    }
}

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
)]
#[repr(C)]
pub struct ContentFlags(u32);

bitflags::bitflags! {
    impl ContentFlags: u32 {
        const FIRST_PATCH = 0x00100000;
        const PATCHGO = 0x00200000;
        const REMASTER = 0x00400000;
        const PS_CLOUD = 0x00800000;
        const DELTA_PATCH_X = 0x01000000;
        const GD_AC = 0x02000000;
        const NON_GAME = 0x04000000;
        const UNKNOWN_1 = 0x08000000;
        const UNKNOWN_2 = 0x10000000;
        const CUMULATIVE_PATCH_X = 0x20000000;
        const SUBSEQUENT_PATCH = 0x40000000;
        const DELTA_PATCH = 0x41000000;
        const CUMULATIVE_PATCH = 0x60000000;
    }
}

impl fmt::Display for ContentFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return write!(f, "(none)");
        }

        let mut first = true;
        let mut write_flag = |name: &str| -> fmt::Result {
            if !first {
                write!(f, ", ")?;
            }
            first = false;
            write!(f, "{}", name)
        };

        // Check compound flags first (they include multiple bits)
        if self.contains(Self::CUMULATIVE_PATCH) {
            write_flag("Cumulative Patch")?;
        } else if self.contains(Self::DELTA_PATCH) {
            write_flag("Delta Patch")?;
        } else {
            // Check individual flags
            if self.contains(Self::FIRST_PATCH) {
                write_flag("First Patch")?;
            }
            if self.contains(Self::PATCHGO) {
                write_flag("PatchGo")?;
            }
            if self.contains(Self::REMASTER) {
                write_flag("Remaster")?;
            }
            if self.contains(Self::PS_CLOUD) {
                write_flag("PS Cloud")?;
            }
            if self.contains(Self::DELTA_PATCH_X) {
                write_flag("Delta Patch X")?;
            }
            if self.contains(Self::GD_AC) {
                write_flag("GD/AC")?;
            }
            if self.contains(Self::NON_GAME) {
                write_flag("Non-Game")?;
            }
            if self.contains(Self::UNKNOWN_1) {
                write_flag("Unknown (0x08000000)")?;
            }
            if self.contains(Self::UNKNOWN_2) {
                write_flag("Unknown (0x10000000)")?;
            }
            if self.contains(Self::CUMULATIVE_PATCH_X) {
                write_flag("Cumulative Patch X")?;
            }
            if self.contains(Self::SUBSEQUENT_PATCH) {
                write_flag("Subsequent Patch")?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct DigestTable {
    pub digest_entries1: [u8; 0x20],
    pub digest_entries2: [u8; 0x20],
    pub digest_table_digest: [u8; 0x20],
    pub digest_body_digest: [u8; 0x20],
}

/// Returns a human-readable name for a content type value.
#[must_use]
pub const fn content_type_name(content_type: u32) -> &'static str {
    match content_type {
        0x01 => "GD (Game Data)",
        0x02 => "AC (Additional Content)",
        0x03 => "AL (App License)",
        0x04 => "DP (Delta Patch)",
        0x05 => "DP (Cumulative Patch)", // sometimes same as 0x04
        0x06 => "Remaster",
        0x1A => "GD (Game Data)",
        0x1B => "AC (Additional Content)",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for a DRM type value.
#[must_use]
pub const fn drm_type_name(drm_type: u32) -> &'static str {
    match drm_type {
        0x0 => "None",
        0x1 => "PS4",
        0xD => "PS4 (Free)",
        0xF => "PS4",
        _ => "Unknown",
    }
}

/// Parsed PKG header information.
#[derive(Debug)]
#[must_use]
pub struct PkgHeader {
    raw_header: PkgHeaderRaw,
}

impl PkgHeader {
    /// Parses a PKG header from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is too small or has an invalid magic number.
    pub fn read(pkg: &[u8]) -> Result<Self, ReadError> {
        // Check size first so we can read without checking bound.
        snafu::ensure!(pkg.len() >= 0x1000, TooSmallSnafu);

        let (raw_header, _) =
            PkgHeaderRaw::try_read_from_prefix(pkg).map_err(|_| InvalidSourceBytesSnafu.build())?;

        // Check magic.
        snafu::ensure!(raw_header.pkg_magic.get() == PKG_MAGIC, InvalidMagicSnafu);

        Ok(Self { raw_header })
    }

    /// Returns the number of entries in the PKG.
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.raw_header.pkg_entry_count.get() as _
    }

    /// Returns the offset to the entry table.
    #[must_use]
    pub const fn table_offset(&self) -> usize {
        self.raw_header.pkg_table_offset.get() as _
    }

    /// Returns the offset to the PFS image.
    #[must_use]
    pub const fn pfs_offset(&self) -> usize {
        self.raw_header.pfs_image_offset.get() as _
    }

    /// Returns the size of the PFS image.
    #[must_use]
    pub const fn pfs_size(&self) -> usize {
        self.raw_header.pfs_image_size.get() as _
    }

    /// Returns the content ID.
    #[must_use]
    pub fn content_id(&self) -> &ContentId {
        &self.raw_header.pkg_content_id
    }

    /// Returns the PKG type.
    #[must_use]
    pub const fn pkg_type(&self) -> u32 {
        self.raw_header.pkg_type.get()
    }

    /// Returns the DRM type.
    #[must_use]
    pub const fn drm_type(&self) -> u32 {
        self.raw_header.pkg_drm_type.get()
    }

    /// Returns the human-readable name for the DRM type.
    #[must_use]
    pub const fn drm_type_name(&self) -> &'static str {
        drm_type_name(self.drm_type())
    }

    /// Returns the content type.
    #[must_use]
    pub const fn content_type(&self) -> u32 {
        self.raw_header.pkg_content_type.get()
    }

    /// Returns the human-readable name for the content type.
    #[must_use]
    pub const fn content_type_name(&self) -> &'static str {
        content_type_name(self.content_type())
    }

    /// Returns the content flags.
    #[must_use]
    pub const fn content_flags(&self) -> ContentFlags {
        ContentFlags::from_bits_truncate(self.raw_header.pkg_content_flags.get())
    }

    /// Returns the total PKG file size.
    #[must_use]
    pub const fn pkg_size(&self) -> u64 {
        self.raw_header.pkg_size.get()
    }

    /// Returns the file count.
    #[must_use]
    pub const fn file_count(&self) -> u32 {
        self.raw_header.pkg_file_count.get()
    }

    /// Returns the raw header.
    #[must_use]
    pub const fn raw_header(&self) -> &PkgHeaderRaw {
        &self.raw_header
    }
}
