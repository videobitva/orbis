use aes::Aes128;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::cmp::min;
use std::io;
use xts_mode::{Xts128, get_tweak_default};

pub(crate) const XTS_BLOCK_SIZE: usize = 0x1000;

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

/// Gets data key and tweak key from EKPFS and seed.
pub(crate) fn get_xts_keys(ekpfs: &[u8], seed: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
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
pub(crate) struct UnencryptedSlice<'a> {
    data: &'a [u8],
}

impl<'a> UnencryptedSlice<'a> {
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
pub(crate) struct EncryptedSlice<'a> {
    data: &'a [u8],
    decryptor: Xts128<Aes128>,
    /// XTS block index where encryption begins.
    encrypted_start: usize,
}

impl<'a> EncryptedSlice<'a> {
    pub fn new(data: &'a [u8], decryptor: Xts128<Aes128>, encrypted_start: usize) -> Self {
        Self {
            data,
            decryptor,
            encrypted_start,
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
                self.decryptor.decrypt_sector(&mut scratch, tweak);
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
