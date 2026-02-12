use aes::Aes128;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::cmp::min;
use std::collections::BTreeMap;
use std::io;
use std::sync::RwLock;
use xts_mode::{Xts128, get_tweak_default};

/// The size of a single XTS encryption sector (4 KiB).
pub const XTS_BLOCK_SIZE: usize = 0x1000;

/// Encapsulates a PFS image with positional read support.
///
/// This trait provides thread-safe, stateless access to PFS image data.
/// Unlike `Read + Seek`, each call specifies its own offset, enabling
/// concurrent reads from multiple threads without synchronization.
pub trait Image: Send + Sync {
    /// Reads bytes from the image at the given offset into `buf`.
    ///
    /// Returns the number of bytes actually read. A short read indicates
    /// the end of the image was reached.
    fn read_at(&self, offset: u64, output_buf: &mut [u8]) -> io::Result<usize>;

    /// Reads exactly `buf.len()` bytes from `image` at `offset`.
    ///
    /// Returns [`io::ErrorKind::UnexpectedEof`] if the image ends before the buffer
    /// is filled.
    fn read_exact_at(&self, offset: u64, output_buf: &mut [u8]) -> io::Result<()> {
        let mut total = 0;

        while total < output_buf.len() {
            let n = self.read_at(offset + total as u64, &mut output_buf[total..])?;

            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF in image",
                ));
            }

            total += n;
        }

        Ok(())
    }

    /// Returns the total length of the image in bytes.
    fn len(&self) -> u64;

    /// Returns `true` if the image is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// `Image` is implemented for `Box<dyn Image>` so that type-erased images
/// can be used where a concrete `I: Image` is expected (e.g. in [`crate::Pfs`]).
impl Image for Box<dyn Image + '_> {
    fn read_at(&self, offset: u64, output_buf: &mut [u8]) -> io::Result<usize> {
        (**self).read_at(offset, output_buf)
    }

    fn read_exact_at(&self, offset: u64, output_buf: &mut [u8]) -> io::Result<()> {
        (**self).read_exact_at(offset, output_buf)
    }

    fn len(&self) -> u64 {
        (**self).len()
    }
}

/// Derives the XTS data key and tweak key from EKPFS and the PFS key seed.
pub fn get_xts_keys(ekpfs: &[u8], seed: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let mut hmac = Hmac::<Sha256>::new_from_slice(ekpfs).unwrap();
    hmac.update(&[0x01, 0x00, 0x00, 0x00]);
    hmac.update(seed);

    let secret = hmac.finalize().into_bytes();
    let mut data_key: [u8; 16] = Default::default();
    let mut tweak_key: [u8; 16] = Default::default();

    tweak_key.copy_from_slice(&secret[..16]);
    data_key.copy_from_slice(&secret[16..]);

    (data_key, tweak_key)
}

/// Unencrypted PFS image backed by a byte slice.
///
/// Reads are pure slice indexing — no locks, no allocation, no state.
pub struct UnencryptedSlice<'a> {
    data: &'a [u8],
}

impl<'a> UnencryptedSlice<'a> {
    /// Creates a new unencrypted image backed by `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl Image for UnencryptedSlice<'_> {
    fn read_at(&self, offset: u64, output_buf: &mut [u8]) -> io::Result<usize> {
        let start = offset as usize;

        if start >= self.data.len() {
            return Ok(0);
        }

        let available = self.data.len() - start;
        let n = min(output_buf.len(), available);

        output_buf[..n].copy_from_slice(&self.data[start..start + n]);

        Ok(n)
    }

    fn len(&self) -> u64 {
        self.data.len() as u64
    }
}

/// Encrypted PFS image backed by a byte slice.
///
/// Uses XTS-AES-128 for sector-level decryption. Each 4 KiB sector is
/// independently decryptable, enabling sparse access and re-encryption.
pub struct EncryptedSlice<'a> {
    data: &'a [u8],
    cipher: Xts128<Aes128>,
    /// XTS block index where encryption begins.
    encrypted_start: usize,
}

impl<'a> EncryptedSlice<'a> {
    /// Creates a new encrypted image backed by `data`.
    pub fn new(data: &'a [u8], cipher: Xts128<Aes128>, encrypted_start: usize) -> Self {
        Self {
            data,
            cipher,
            encrypted_start,
        }
    }

    /// Returns the XTS-AES-128 cipher used for encryption/decryption.
    pub fn cipher(&self) -> &Xts128<Aes128> {
        &self.cipher
    }

    /// Returns the XTS sector index where encryption begins.
    ///
    /// Sectors before this index are stored in plaintext (typically the PFS header block).
    pub fn encrypted_start(&self) -> usize {
        self.encrypted_start
    }

    /// Encrypts a single XTS sector in-place.
    ///
    /// `sector_data` must be exactly [`XTS_BLOCK_SIZE`] bytes.
    /// If `sector_index` is before [`encrypted_start()`](Self::encrypted_start),
    /// the data is left unchanged (plaintext region).
    pub fn encrypt_sector(&self, sector_index: usize, sector_data: &mut [u8]) {
        debug_assert_eq!(sector_data.len(), XTS_BLOCK_SIZE);
        if sector_index >= self.encrypted_start {
            let tweak = get_tweak_default(sector_index as u128);
            self.cipher.encrypt_sector(sector_data, tweak);
        }
    }

    /// Decrypts a single XTS sector in-place.
    ///
    /// `sector_data` must be exactly [`XTS_BLOCK_SIZE`] bytes.
    pub fn decrypt_sector(&self, sector_index: usize, sector_data: &mut [u8]) {
        debug_assert_eq!(sector_data.len(), XTS_BLOCK_SIZE);
        if sector_index >= self.encrypted_start {
            let tweak = get_tweak_default(sector_index as u128);
            self.cipher.decrypt_sector(sector_data, tweak);
        }
    }
}

impl Image for EncryptedSlice<'_> {
    fn read_at(&self, offset: u64, output_buf: &mut [u8]) -> io::Result<usize> {
        let len = self.data.len() as u64;

        if output_buf.is_empty() || offset >= len {
            return Ok(0);
        }

        let mut copied = 0;
        let mut pos = offset;
        let mut scratch = vec![0u8; XTS_BLOCK_SIZE];

        while copied < output_buf.len() && pos < len {
            let block = (pos as usize) / XTS_BLOCK_SIZE;
            let offset_in_block = (pos as usize) % XTS_BLOCK_SIZE;
            let block_start = block * XTS_BLOCK_SIZE;

            // Copy XTS block from backing slice into scratch buffer.
            let src = self
                .data
                .get(block_start..block_start + XTS_BLOCK_SIZE)
                .ok_or_else(|| io::Error::other(format!("XTS block #{} out of bounds", block)))?;

            scratch.copy_from_slice(src);

            // Decrypt if in encrypted region.
            if block >= self.encrypted_start {
                let tweak = get_tweak_default(block as _);
                self.cipher.decrypt_sector(&mut scratch, tweak);
            }

            // Copy the relevant portion to the output buffer.
            let available = XTS_BLOCK_SIZE - offset_in_block;
            let remaining_file = (len - pos) as usize;
            let n = min(min(available, remaining_file), output_buf.len() - copied);

            output_buf[copied..copied + n]
                .copy_from_slice(&scratch[offset_in_block..offset_in_block + n]);

            copied += n;
            pos += n as u64;
        }

        Ok(copied)
    }

    fn len(&self) -> u64 {
        self.data.len() as u64
    }
}

// ---------------------------------------------------------------------------
// Marker traits for compile-time capability propagation
// ---------------------------------------------------------------------------

/// Marker trait: the image stack contains an encryption layer.
///
/// This trait propagates outward from [`EncryptedSlice`] through every wrapper
/// (`PfscImage`, `CowImage`, [`PfsFileImage`](crate::file::PfsFileImage)),
/// enabling compile-time–gated access to XTS encryption capabilities.
pub trait HasEncryption: Image {
    /// Returns the XTS-AES-128 cipher for encryption/decryption.
    fn xts_cipher(&self) -> &Xts128<Aes128>;

    /// Returns the XTS sector index where encryption begins.
    fn xts_encrypted_start(&self) -> usize;
}

impl HasEncryption for EncryptedSlice<'_> {
    fn xts_cipher(&self) -> &Xts128<Aes128> {
        &self.cipher
    }

    fn xts_encrypted_start(&self) -> usize {
        self.encrypted_start
    }
}

/// Marker trait: the image stack has a CoW overlay with write support.
pub trait HasOverlay: Image {
    /// Returns the overlay segments as `(offset, data)` pairs.
    fn overlay_segments(&self) -> Vec<(u64, Vec<u8>)>;

    /// Writes data into the overlay at the given offset.
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()>;
}

// ---------------------------------------------------------------------------
// Copy-on-Write overlay image
// ---------------------------------------------------------------------------

/// A copy-on-write overlay over an existing [`Image`].
///
/// `CowImage` wraps any `Image` and intercepts reads through a sparse overlay
/// of modified byte segments. Unmodified regions fall through to the base image.
/// This enables efficient, sparse modifications to a large PFS/PKG image
/// without rewriting the entire file.
///
/// # Design
///
/// Modified data is stored in a `BTreeMap<u64, Vec<u8>>` where each key is
/// the start offset of a contiguous modified segment. The map maintains the
/// invariant that **segments never overlap and are never adjacent** — writes
/// that touch existing segments are merged eagerly.
///
/// Reads composite overlay patches over base-image data in a single pass,
/// so the caller always sees a coherent view.
///
/// # Thread Safety
///
/// Implements [`Image`] (which requires `Send + Sync`). Internal state is
/// protected by an [`RwLock`]: reads take a shared lock, writes take an
/// exclusive lock. Multiple concurrent readers do not block each other.
///
/// # Example
///
/// ```no_run
/// use orbis_pfs::image::{CowImage, Image};
///
/// fn patch_image(base: impl Image) -> std::io::Result<()> {
///     let cow = CowImage::new(base);
///
///     // Write a small patch at offset 0x1000.
///     cow.write_at(0x1000, b"patched!")?;
///
///     // Reads transparently merge base + overlay.
///     let mut buf = [0u8; 16];
///     cow.read_at(0x1000, &mut buf)?;
///     assert_eq!(&buf[..8], b"patched!");
///
///     Ok(())
/// }
/// ```
pub struct CowImage<I: Image> {
    base: I,
    /// Sparse overlay: start-offset → modified bytes.
    ///
    /// Invariants maintained by [`Self::write_at`]:
    /// - No two segments overlap.
    /// - No two segments are directly adjacent (they get merged).
    overlay: RwLock<BTreeMap<u64, Vec<u8>>>,
    /// Current logical length (may grow beyond base length on writes past end).
    logical_len: RwLock<u64>,
}

impl<I: Image> CowImage<I> {
    /// Creates a new copy-on-write overlay over `base`.
    pub fn new(base: I) -> Self {
        let len = base.len();

        Self {
            base,
            overlay: RwLock::new(BTreeMap::new()),
            logical_len: RwLock::new(len),
        }
    }

    /// Writes `data` into the overlay at `offset`.
    ///
    /// The write is merged with any existing overlay segments it touches or
    /// is adjacent to, keeping the segment map compact.
    ///
    /// This may extend the logical length of the image if writing past the
    /// current end.
    pub fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let new_end = offset.checked_add(data.len() as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "write range overflows u64")
        })?;
        let mut overlay = self
            .overlay
            .write()
            .map_err(|_| io::Error::other("overlay lock poisoned"))?;

        // Update logical length.
        {
            let mut len = self
                .logical_len
                .write()
                .map_err(|_| io::Error::other("length lock poisoned"))?;

            if new_end > *len {
                *len = new_end;
            }
        }

        // Collect all existing segments that the new write overlaps or is
        // adjacent to. "Adjacent" means the gap between them is zero — we
        // merge those to keep the map compact.
        let write_start = offset;
        let write_end = new_end; // exclusive

        // Find segments whose range intersects or is adjacent to [write_start, write_end).
        // A segment (seg_start, seg_data) covers [seg_start, seg_start + seg_data.len()).
        // It overlaps/adjoins our write if:
        //   seg_start <= write_end  AND  seg_start + seg_data.len() >= write_start

        // Collect keys of overlapping segments. We scan from the last segment
        // that starts at or before write_end.
        let mut to_merge: Vec<(u64, Vec<u8>)> = Vec::new();

        // Segments that start *at or before* write_end and end *at or after* write_start.
        let keys_to_remove: Vec<u64> = overlay
            .range(..=write_end)
            .rev()
            .take_while(|&(seg_start, seg_data)| *seg_start + seg_data.len() as u64 >= write_start)
            .map(|(k, _)| *k)
            .collect();

        for k in &keys_to_remove {
            if let Some(v) = overlay.remove(k) {
                to_merge.push((*k, v));
            }
        }

        if to_merge.is_empty() {
            // No overlaps — just insert.
            overlay.insert(offset, data.to_vec());
        } else {
            // Compute the bounding range of the merge.
            let merged_start = to_merge
                .iter()
                .map(|(s, _)| *s)
                .min()
                .unwrap()
                .min(write_start);
            let merged_end = to_merge
                .iter()
                .map(|(s, d)| *s + d.len() as u64)
                .max()
                .unwrap()
                .max(write_end);

            let merged_len = (merged_end - merged_start) as usize;
            let mut merged = vec![0u8; merged_len];

            // Fill from base image for any gaps that aren't covered by
            // existing overlay segments or the new write.
            self.base
                .read_exact_at(merged_start, &mut merged)
                .or_else(|e| {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        // Base image may be shorter; read what we can.
                        let base_len = self.base.len();
                        if merged_start < base_len {
                            let avail = (base_len - merged_start) as usize;
                            let read_len = min(avail, merged_len);
                            self.base
                                .read_exact_at(merged_start, &mut merged[..read_len])?;
                        }
                        // Bytes beyond base remain zero-filled.
                        Ok(())
                    } else {
                        Err(e)
                    }
                })?;

            // Layer existing overlay segments on top of the base data.
            for (seg_start, seg_data) in &to_merge {
                let local = (*seg_start - merged_start) as usize;
                merged[local..local + seg_data.len()].copy_from_slice(seg_data);
            }

            // Layer the new write on top of everything.
            let local = (write_start - merged_start) as usize;
            merged[local..local + data.len()].copy_from_slice(data);

            overlay.insert(merged_start, merged);
        }

        Ok(())
    }

    /// Returns the number of bytes stored in the overlay.
    ///
    /// This is the total amount of modified data — useful for estimating
    /// the "dirty" footprint.
    pub fn overlay_bytes(&self) -> usize {
        self.overlay
            .read()
            .map(|o| o.values().map(|v| v.len()).sum())
            .unwrap_or(0)
    }

    /// Returns the number of contiguous segments in the overlay.
    pub fn overlay_segment_count(&self) -> usize {
        self.overlay.read().map(|o| o.len()).unwrap_or(0)
    }

    /// Returns an iterator over the overlay segments as `(offset, data)` pairs.
    ///
    /// This is useful for serializing only the modified portions of the image
    /// (e.g. writing a patch file or updating specific sectors on disk).
    pub fn overlay_segments(&self) -> Vec<(u64, Vec<u8>)> {
        self.overlay
            .read()
            .map(|o| o.iter().map(|(&k, v)| (k, v.clone())).collect())
            .unwrap_or_default()
    }

    /// Returns a reference to the base image.
    pub fn base(&self) -> &I {
        &self.base
    }

    /// Consumes the `CowImage` and returns the base image and overlay segments.
    pub fn into_parts(self) -> (I, BTreeMap<u64, Vec<u8>>) {
        (self.base, self.overlay.into_inner().unwrap_or_default())
    }
}

impl<I: Image + std::fmt::Debug> std::fmt::Debug for CowImage<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CowImage")
            .field("base", &self.base)
            .field("overlay_segments", &self.overlay_segment_count())
            .field("overlay_bytes", &self.overlay_bytes())
            .field("logical_len", &self.len())
            .finish()
    }
}

impl<I: Image> Image for CowImage<I> {
    fn read_at(&self, offset: u64, output_buf: &mut [u8]) -> io::Result<usize> {
        let logical_len = *self
            .logical_len
            .read()
            .map_err(|_| io::Error::other("length lock poisoned"))?;

        if output_buf.is_empty() || offset >= logical_len {
            return Ok(0);
        }

        // Clamp to logical length.
        let available = (logical_len - offset) as usize;
        let read_len = min(output_buf.len(), available);
        let buf = &mut output_buf[..read_len];

        // Step 1: Fill from base image (may be short if offset is past base end).
        let base_len = self.base.len();

        if offset < base_len {
            let base_avail = min((base_len - offset) as usize, read_len);
            self.base.read_exact_at(offset, &mut buf[..base_avail])?;

            // Zero-fill any portion beyond the base.
            buf[base_avail..].fill(0);
        } else {
            // Entirely beyond base — zero-fill (these are extension bytes).
            buf.fill(0);
        }

        // Step 2: Apply overlay patches.
        let overlay = self
            .overlay
            .read()
            .map_err(|_| io::Error::other("overlay lock poisoned"))?;

        let read_start = offset;
        let read_end = offset + read_len as u64;

        // Find all segments that could overlap [read_start, read_end).
        // We need segments where seg_start < read_end AND seg_end > read_start.
        //
        // Use range(..read_end) and iterate backwards until seg_end <= read_start.
        for (&seg_start, seg_data) in overlay.range(..read_end).rev() {
            let seg_end = seg_start + seg_data.len() as u64;

            if seg_end <= read_start {
                break; // No more overlaps possible (segments are sorted).
            }

            // Compute the overlapping range in absolute offsets.
            let overlap_start = seg_start.max(read_start);
            let overlap_end = seg_end.min(read_end);

            // Map to local offsets in the output buffer and segment data.
            let buf_offset = (overlap_start - read_start) as usize;
            let seg_offset = (overlap_start - seg_start) as usize;
            let copy_len = (overlap_end - overlap_start) as usize;

            buf[buf_offset..buf_offset + copy_len]
                .copy_from_slice(&seg_data[seg_offset..seg_offset + copy_len]);
        }

        Ok(read_len)
    }

    fn len(&self) -> u64 {
        *self.logical_len.read().unwrap_or_else(|e| e.into_inner())
    }
}

// --- Marker trait propagation for CowImage ---

impl<I: Image + HasEncryption> HasEncryption for CowImage<I> {
    fn xts_cipher(&self) -> &Xts128<Aes128> {
        self.base.xts_cipher()
    }

    fn xts_encrypted_start(&self) -> usize {
        self.base.xts_encrypted_start()
    }
}

impl<I: Image> HasOverlay for CowImage<I> {
    fn overlay_segments(&self) -> Vec<(u64, Vec<u8>)> {
        CowImage::overlay_segments(self)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        CowImage::write_at(self, offset, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A simple in-memory image for testing.
    struct MemImage(Vec<u8>);

    impl Image for MemImage {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            let start = offset as usize;

            if start >= self.0.len() {
                return Ok(0);
            }

            let avail = self.0.len() - start;
            let n = min(buf.len(), avail);
            buf[..n].copy_from_slice(&self.0[start..start + n]);
            Ok(n)
        }

        fn len(&self) -> u64 {
            self.0.len() as u64
        }
    }

    #[test]
    fn read_through_no_overlay() {
        let base = MemImage(vec![0xAA; 100]);
        let cow = CowImage::new(base);

        let mut buf = [0u8; 10];
        let n = cow.read_at(50, &mut buf).unwrap();
        assert_eq!(n, 10);
        assert_eq!(buf, [0xAA; 10]);
    }

    #[test]
    fn write_then_read() {
        let base = MemImage(vec![0x00; 100]);
        let cow = CowImage::new(base);

        cow.write_at(10, &[0xFF; 5]).unwrap();

        // Read spanning the patch boundary.
        let mut buf = [0u8; 20];
        let n = cow.read_at(5, &mut buf).unwrap();
        assert_eq!(n, 20);

        // Bytes 5..10 from base (0x00).
        assert_eq!(&buf[0..5], &[0x00; 5]);
        // Bytes 10..15 from overlay (0xFF).
        assert_eq!(&buf[5..10], &[0xFF; 5]);
        // Bytes 15..25 from base (0x00).
        assert_eq!(&buf[10..20], &[0x00; 10]);
    }

    #[test]
    fn overlapping_writes_merge() {
        let base = MemImage(vec![0x00; 100]);
        let cow = CowImage::new(base);

        cow.write_at(10, &[0xAA; 10]).unwrap(); // [10..20)
        cow.write_at(15, &[0xBB; 10]).unwrap(); // [15..25) — overlaps

        assert_eq!(cow.overlay_segment_count(), 1, "segments should be merged");

        let mut buf = [0u8; 20];
        cow.read_at(10, &mut buf).unwrap();

        // [10..15) = 0xAA, [15..25) = 0xBB, [25..30) = 0x00
        assert_eq!(&buf[0..5], &[0xAA; 5]);
        assert_eq!(&buf[5..15], &[0xBB; 10]);
        assert_eq!(&buf[15..20], &[0x00; 5]);
    }

    #[test]
    fn adjacent_writes_merge() {
        let base = MemImage(vec![0x00; 100]);
        let cow = CowImage::new(base);

        cow.write_at(10, &[0xAA; 5]).unwrap(); // [10..15)
        cow.write_at(15, &[0xBB; 5]).unwrap(); // [15..20) — adjacent

        assert_eq!(
            cow.overlay_segment_count(),
            1,
            "adjacent segments should merge"
        );

        let mut buf = [0u8; 10];
        cow.read_at(10, &mut buf).unwrap();
        assert_eq!(&buf[..5], &[0xAA; 5]);
        assert_eq!(&buf[5..], &[0xBB; 5]);
    }

    #[test]
    fn write_extends_image() {
        let base = MemImage(vec![0xAA; 50]);
        let cow = CowImage::new(base);
        assert_eq!(cow.len(), 50);

        // Write past the end.
        cow.write_at(45, &[0xBB; 20]).unwrap();
        assert_eq!(cow.len(), 65);

        let mut buf = [0u8; 20];
        let n = cow.read_at(45, &mut buf).unwrap();
        assert_eq!(n, 20);
        assert_eq!(&buf[..20], &[0xBB; 20]);
    }

    #[test]
    fn read_past_end_returns_short() {
        let base = MemImage(vec![0xAA; 10]);
        let cow = CowImage::new(base);

        let mut buf = [0u8; 20];
        let n = cow.read_at(5, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], &[0xAA; 5]);
    }

    #[test]
    fn empty_write_is_noop() {
        let base = MemImage(vec![0xAA; 10]);
        let cow = CowImage::new(base);

        cow.write_at(5, &[]).unwrap();
        assert_eq!(cow.overlay_segment_count(), 0);
    }

    #[test]
    fn multiple_disjoint_segments() {
        let base = MemImage(vec![0x00; 100]);
        let cow = CowImage::new(base);

        cow.write_at(10, &[0xAA; 5]).unwrap(); // [10..15)
        cow.write_at(50, &[0xBB; 5]).unwrap(); // [50..55)
        cow.write_at(80, &[0xCC; 5]).unwrap(); // [80..85)

        assert_eq!(cow.overlay_segment_count(), 3);

        let mut buf = [0u8; 100];
        cow.read_at(0, &mut buf).unwrap();

        assert_eq!(&buf[10..15], &[0xAA; 5]);
        assert_eq!(&buf[50..55], &[0xBB; 5]);
        assert_eq!(&buf[80..85], &[0xCC; 5]);

        // Gaps should be base (0x00).
        assert_eq!(&buf[0..10], &[0x00; 10]);
        assert_eq!(&buf[15..50], &[0x00; 35]);
    }

    #[test]
    fn overwrite_within_existing_segment() {
        let base = MemImage(vec![0x00; 100]);
        let cow = CowImage::new(base);

        cow.write_at(10, &[0xAA; 20]).unwrap(); // [10..30)
        cow.write_at(15, &[0xBB; 5]).unwrap(); // [15..20) — inside existing

        assert_eq!(cow.overlay_segment_count(), 1);

        let mut buf = [0u8; 20];
        cow.read_at(10, &mut buf).unwrap();

        assert_eq!(&buf[0..5], &[0xAA; 5]); // [10..15)
        assert_eq!(&buf[5..10], &[0xBB; 5]); // [15..20)
        assert_eq!(&buf[10..20], &[0xAA; 10]); // [20..30)
    }

    #[test]
    fn write_bridges_two_segments() {
        let base = MemImage(vec![0x00; 100]);
        let cow = CowImage::new(base);

        cow.write_at(10, &[0xAA; 5]).unwrap(); // [10..15)
        cow.write_at(25, &[0xCC; 5]).unwrap(); // [25..30)
        assert_eq!(cow.overlay_segment_count(), 2);

        // Bridge them.
        cow.write_at(13, &[0xBB; 15]).unwrap(); // [13..28) — spans both
        assert_eq!(cow.overlay_segment_count(), 1);

        let mut buf = [0u8; 25];
        cow.read_at(8, &mut buf).unwrap();

        assert_eq!(&buf[0..2], &[0x00; 2]); // [8..10) base
        assert_eq!(&buf[2..5], &[0xAA; 3]); // [10..13) original overlay
        assert_eq!(&buf[5..20], &[0xBB; 15]); // [13..28) bridge write
        assert_eq!(&buf[20..22], &[0xCC; 2]); // [28..30) trailing overlay
        assert_eq!(&buf[22..25], &[0x00; 3]); // [30..33) base
    }

    #[test]
    fn overlay_segments_roundtrip() {
        let base = MemImage(vec![0x00; 100]);
        let cow = CowImage::new(base);

        cow.write_at(10, &[0xAA; 5]).unwrap();
        cow.write_at(50, &[0xBB; 3]).unwrap();

        let segments = cow.overlay_segments();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0], (10, vec![0xAA; 5]));
        assert_eq!(segments[1], (50, vec![0xBB; 3]));
    }

    #[test]
    fn into_parts_returns_overlay() {
        let base = MemImage(vec![0x00; 50]);
        let cow = CowImage::new(base);

        cow.write_at(5, &[0xFF; 10]).unwrap();

        let (_, overlay) = cow.into_parts();
        assert_eq!(overlay.len(), 1);
        assert_eq!(overlay[&5], vec![0xFF; 10]);
    }
}
