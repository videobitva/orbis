use snafu::Snafu;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use zerocopy::byteorder::big_endian::{U32, U64};

use std::path::{Path, PathBuf};

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum EntryError {
    #[snafu(display("source buffer is too short"))]
    SourceTooShort,
}

type Result<T, E = EntryError> = std::result::Result<T, E>;

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct PkgEntryRaw {
    id: U32,
    filename_offset: U32,
    flags1: U32,
    flags2: U32,
    data_offset: U32,
    data_size: U32,
    padding: U64,
}

#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct PkgEntry {
    raw_entry: PkgEntryRaw,
}

impl PkgEntry {
    pub const RAW_SIZE: usize = size_of::<PkgEntryRaw>();

    /// Reads an entry from raw bytes.
    pub fn read(raw: &[u8]) -> Result<Self> {
        let (raw_entry, _) =
            PkgEntryRaw::read_from_prefix(raw).map_err(|_| SourceTooShortSnafu.build())?;

        Ok(Self { raw_entry })
    }

    /// Returns the entry ID.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.raw_entry.id.get()
    }

    /// Returns the parsed entry identifier.
    #[must_use]
    pub const fn entry_id(&self) -> EntryId {
        EntryId::from_u32(self.id())
    }

    /// Returns `true` if this entry is encrypted.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.raw_entry.flags1.get() & 0x80000000 != 0
    }

    /// Returns the key index used for encryption.
    #[must_use]
    pub const fn key_index(&self) -> usize {
        ((self.raw_entry.flags2.get() & 0xf000) >> 12) as _
    }

    /// Returns the data offset within the PKG file.
    #[must_use]
    pub const fn data_offset(&self) -> usize {
        self.raw_entry.data_offset.get() as _
    }

    /// Returns the data size in bytes.
    #[must_use]
    pub const fn data_size(&self) -> usize {
        self.raw_entry.data_size.get() as _
    }

    /// Converts the entry to its raw byte representation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.raw_entry.as_bytes()
    }

    /// Converts the entry ID to a filesystem path relative to the given base.
    ///
    /// Returns `None` if the entry ID is not recognized.
    #[must_use]
    pub fn to_path<B: AsRef<Path>>(&self, base: B) -> Option<PathBuf> {
        self.entry_id().to_path(base)
    }
}

/// Known PKG entry identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EntryId {
    // Metadata entries (0x0001 - 0x0200)
    Digests,
    EntryKeys,
    PfsImageKey,
    GeneralDigests,
    Metas,
    EntryNames,

    // License and system entries (0x0400 - 0x0409)
    LicenseDat,
    LicenseInfo,
    NptitleDat,
    NpbindDat,
    SelfinfoDat,
    ImageinfoDat,
    TargetDeltainfoDat,
    OriginDeltainfoDat,
    PsreservedDat,

    // Content entries (0x1000 - 0x100E)
    ParamSfo,
    PlaygoChunkDat,
    PlaygoChunkSha,
    PlaygoManifestXml,
    PronunciationXml,
    PronunciationSig,
    Pic1Png,
    PubtoolinfoDat,
    AppPlaygoChunkDat,
    AppPlaygoChunkSha,
    AppPlaygoManifestXml,
    ShareparamJson,
    ShareoverlayimagePng,
    SaveDataPng,
    ShareprivacyguardimagePng,

    // Icon entries (0x1200 - 0x121F)
    Icon0Png,
    /// `icon0_00.png` .. `icon0_30.png`
    Icon0PngIndexed(u8),

    // Picture entries (0x1220 - 0x125F)
    Pic0Png,
    Snd0At9,
    /// `pic1_00.png` .. `pic1_30.png`
    Pic1PngIndexed(u8),

    // Changeinfo entries (0x1260 - 0x127F)
    ChangeinfoXml,
    /// `changeinfo_00.xml` .. `changeinfo_30.xml`
    ChangeinfoXmlIndexed(u8),

    // DDS entries (0x1280 - 0x12DF)
    Icon0Dds,
    /// `icon0_00.dds` .. `icon0_30.dds`
    Icon0DdsIndexed(u8),
    Pic0Dds,
    Pic1Dds,
    /// `pic1_00.dds` .. `pic1_30.dds`
    Pic1DdsIndexed(u8),

    // Trophy entries (0x1400 - 0x1463)
    /// `trophy00.trp` .. `trophy99.trp`
    Trophy(u8),

    /// Unrecognized entry ID.
    Unknown(u32),
}

impl EntryId {
    /// Returns the raw numeric entry ID.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            // Metadata entries
            Self::Digests => 0x00000001,
            Self::EntryKeys => 0x00000010,
            Self::PfsImageKey => 0x00000020,
            Self::GeneralDigests => 0x00000080,
            Self::Metas => 0x00000100,
            Self::EntryNames => 0x00000200,

            // License and system entries
            Self::LicenseDat => 0x00000400,
            Self::LicenseInfo => 0x00000401,
            Self::NptitleDat => 0x00000402,
            Self::NpbindDat => 0x00000403,
            Self::SelfinfoDat => 0x00000404,
            Self::ImageinfoDat => 0x00000406,
            Self::TargetDeltainfoDat => 0x00000407,
            Self::OriginDeltainfoDat => 0x00000408,
            Self::PsreservedDat => 0x00000409,

            // Content entries
            Self::ParamSfo => 0x00001000,
            Self::PlaygoChunkDat => 0x00001001,
            Self::PlaygoChunkSha => 0x00001002,
            Self::PlaygoManifestXml => 0x00001003,
            Self::PronunciationXml => 0x00001004,
            Self::PronunciationSig => 0x00001005,
            Self::Pic1Png => 0x00001006,
            Self::PubtoolinfoDat => 0x00001007,
            Self::AppPlaygoChunkDat => 0x00001008,
            Self::AppPlaygoChunkSha => 0x00001009,
            Self::AppPlaygoManifestXml => 0x0000100a,
            Self::ShareparamJson => 0x0000100b,
            Self::ShareoverlayimagePng => 0x0000100c,
            Self::SaveDataPng => 0x0000100d,
            Self::ShareprivacyguardimagePng => 0x0000100e,

            // Icon entries
            Self::Icon0Png => 0x00001200,
            Self::Icon0PngIndexed(idx) => 0x00001201 + idx as u32,

            // Picture entries
            Self::Pic0Png => 0x00001220,
            Self::Snd0At9 => 0x00001240,
            Self::Pic1PngIndexed(idx) => 0x00001241 + idx as u32,

            // Changeinfo entries
            Self::ChangeinfoXml => 0x00001260,
            Self::ChangeinfoXmlIndexed(idx) => 0x00001261 + idx as u32,

            // DDS entries
            Self::Icon0Dds => 0x00001280,
            Self::Icon0DdsIndexed(idx) => 0x00001281 + idx as u32,
            Self::Pic0Dds => 0x000012a0,
            Self::Pic1Dds => 0x000012c0,
            Self::Pic1DdsIndexed(idx) => 0x000012c1 + idx as u32,

            // Trophy entries
            Self::Trophy(idx) => 0x00001400 + idx as u32,

            Self::Unknown(raw) => raw,
        }
    }

    /// Converts a raw numeric entry ID into an [`EntryId`].
    #[must_use]
    pub const fn from_u32(raw: u32) -> Self {
        match raw {
            // Metadata entries
            0x00000001 => Self::Digests,
            0x00000010 => Self::EntryKeys,
            0x00000020 => Self::PfsImageKey,
            0x00000080 => Self::GeneralDigests,
            0x00000100 => Self::Metas,
            0x00000200 => Self::EntryNames,

            // License and system entries
            0x00000400 => Self::LicenseDat,
            0x00000401 => Self::LicenseInfo,
            0x00000402 => Self::NptitleDat,
            0x00000403 => Self::NpbindDat,
            0x00000404 => Self::SelfinfoDat,
            0x00000406 => Self::ImageinfoDat,
            0x00000407 => Self::TargetDeltainfoDat,
            0x00000408 => Self::OriginDeltainfoDat,
            0x00000409 => Self::PsreservedDat,

            // Content entries
            0x00001000 => Self::ParamSfo,
            0x00001001 => Self::PlaygoChunkDat,
            0x00001002 => Self::PlaygoChunkSha,
            0x00001003 => Self::PlaygoManifestXml,
            0x00001004 => Self::PronunciationXml,
            0x00001005 => Self::PronunciationSig,
            0x00001006 => Self::Pic1Png,
            0x00001007 => Self::PubtoolinfoDat,
            0x00001008 => Self::AppPlaygoChunkDat,
            0x00001009 => Self::AppPlaygoChunkSha,
            0x0000100a => Self::AppPlaygoManifestXml,
            0x0000100b => Self::ShareparamJson,
            0x0000100c => Self::ShareoverlayimagePng,
            0x0000100d => Self::SaveDataPng,
            0x0000100e => Self::ShareprivacyguardimagePng,

            // Icon PNG entries
            0x00001200 => Self::Icon0Png,
            0x00001201..=0x0000121F => Self::Icon0PngIndexed((raw - 0x00001201) as u8),

            // Picture entries
            0x00001220 => Self::Pic0Png,
            0x00001240 => Self::Snd0At9,
            0x00001241..=0x0000125F => Self::Pic1PngIndexed((raw - 0x00001241) as u8),

            // Changeinfo entries
            0x00001260 => Self::ChangeinfoXml,
            0x00001261..=0x0000127F => Self::ChangeinfoXmlIndexed((raw - 0x00001261) as u8),

            // DDS entries
            0x00001280 => Self::Icon0Dds,
            0x00001281..=0x0000129F => Self::Icon0DdsIndexed((raw - 0x00001281) as u8),
            0x000012a0 => Self::Pic0Dds,
            0x000012c0 => Self::Pic1Dds,
            0x000012c1..=0x000012df => Self::Pic1DdsIndexed((raw - 0x000012c1) as u8),

            // Trophy entries
            0x00001400..=0x00001463 => Self::Trophy((raw - 0x00001400) as u8),

            other => Self::Unknown(other),
        }
    }

    /// Converts this entry ID to a filesystem path relative to the given base.
    ///
    /// Returns `None` if the entry ID is not recognized (or cannot be represented).
    #[must_use]
    pub fn to_path<B: AsRef<Path>>(self, base: B) -> Option<PathBuf> {
        let base = base.as_ref();
        Some(match self {
            // Metadata entries
            Self::Digests => base.join("digests"),
            Self::EntryKeys => base.join("entry_keys"),
            Self::PfsImageKey => base.join("image_key"),
            Self::GeneralDigests => base.join("general_digests"),
            Self::Metas => base.join("metas"),
            Self::EntryNames => base.join("entry_names"),

            // License and system entries
            Self::LicenseDat => base.join("license.dat"),
            Self::LicenseInfo => base.join("license.info"),
            Self::NptitleDat => base.join("nptitle.dat"),
            Self::NpbindDat => base.join("npbind.dat"),
            Self::SelfinfoDat => base.join("selfinfo.dat"),
            Self::ImageinfoDat => base.join("imageinfo.dat"),
            Self::TargetDeltainfoDat => base.join("target-deltainfo.dat"),
            Self::OriginDeltainfoDat => base.join("origin-deltainfo.dat"),
            Self::PsreservedDat => base.join("psreserved.dat"),

            // Content entries
            Self::ParamSfo => base.join("param.sfo"),
            Self::PlaygoChunkDat => base.join("playgo-chunk.dat"),
            Self::PlaygoChunkSha => base.join("playgo-chunk.sha"),
            Self::PlaygoManifestXml => base.join("playgo-manifest.xml"),
            Self::PronunciationXml => base.join("pronunciation.xml"),
            Self::PronunciationSig => base.join("pronunciation.sig"),
            Self::Pic1Png => base.join("pic1.png"),
            Self::PubtoolinfoDat => base.join("pubtoolinfo.dat"),
            Self::AppPlaygoChunkDat => base.join("app").join("playgo-chunk.dat"),
            Self::AppPlaygoChunkSha => base.join("app").join("playgo-chunk.sha"),
            Self::AppPlaygoManifestXml => base.join("app").join("playgo-manifest.xml"),
            Self::ShareparamJson => base.join("shareparam.json"),
            Self::ShareoverlayimagePng => base.join("shareoverlayimage.png"),
            Self::SaveDataPng => base.join("save_data.png"),
            Self::ShareprivacyguardimagePng => base.join("shareprivacyguardimage.png"),

            // Icon PNG entries
            Self::Icon0Png => base.join("icon0.png"),
            Self::Icon0PngIndexed(idx) => base.join(format!("icon0_{:02}.png", idx)),

            // Picture entries
            Self::Pic0Png => base.join("pic0.png"),
            Self::Snd0At9 => base.join("snd0.at9"),
            Self::Pic1PngIndexed(idx) => base.join(format!("pic1_{:02}.png", idx)),

            // Changeinfo entries
            Self::ChangeinfoXml => base.join("changeinfo").join("changeinfo.xml"),
            Self::ChangeinfoXmlIndexed(idx) => base
                .join("changeinfo")
                .join(format!("changeinfo_{:02}.xml", idx)),

            // DDS entries
            Self::Icon0Dds => base.join("icon0.dds"),
            Self::Icon0DdsIndexed(idx) => base.join(format!("icon0_{:02}.dds", idx)),
            Self::Pic0Dds => base.join("pic0.dds"),
            Self::Pic1Dds => base.join("pic1.dds"),
            Self::Pic1DdsIndexed(idx) => base.join(format!("pic1_{:02}.dds", idx)),

            // Trophy entries
            Self::Trophy(idx) => base.join("trophy").join(format!("trophy{:02}.trp", idx)),

            Self::Unknown(_) => return None,
        })
    }
}
