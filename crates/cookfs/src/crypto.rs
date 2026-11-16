//! Decryption of the `CFS0003` archives upstream encrypts.
//!
//! A password and the archive's salt derive a 32-byte key through
//! PBKDF2-HMAC-SHA256. `FILE` mode encrypts pages with that key directly.
//! `KEY` and `KEY_INDEX` encrypt them with a random key, stored after the
//! signature encrypted by the derived one alongside a copy of its IV, which is
//! how a wrong password shows. Every encrypted blob is AES-256-CBC with
//! PKCS#7 padding, its IV the 16-byte hash slot the archive keeps for it.

use aes::Aes256;
use aes::cipher::{BlockModeDecrypt, KeyIvInit};
use snafu::ensure;

use crate::codec::{DecodeError, decode_error};

crate::wire::wire_enum! {
    /// How a `CFS0003` archive is encrypted.
    pub struct EncryptionMode(u8) {
        /// Not encrypted.
        NONE = 0,
        /// Pages encrypted with a key derived from the password.
        FILE = 1,
        /// Pages encrypted with a random key, itself encrypted by the password.
        KEY = 2,
        /// As [`Self::KEY`], with the pgindex and fsindex encrypted too.
        KEY_INDEX = 3,
    }
}

/// A `CFS0003` archive's encryption mode and key-derivation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Encryption {
    /// The mode.
    pub mode: EncryptionMode,
    /// The PBKDF2 level, 0 to 31; upstream's default is 15.
    pub level: u8,
}

/// AES's block, and the length of every IV and salt here.
pub(crate) const BLOCK: usize = 16;
/// An AES-256 key.
pub(crate) const KEY_LEN: usize = 32;
/// A stored data key: the key itself, then a copy of the IV it was encrypted under.
pub(crate) const WRAPPED_KEY_LEN: usize = KEY_LEN + BLOCK;

/// The key every encrypted blob in one archive decrypts with.
#[derive(Clone)]
pub(crate) struct Key([u8; KEY_LEN]);

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(..)")
    }
}

/// PBKDF2 rounds per encryption level, below and above level 15.
const ROUNDS_LOW: u32 = 8192;
const ROUNDS_HIGH: u32 = 81_920;

impl Key {
    /// Derives the key a password gives at the archive's salt and level.
    pub(crate) fn derive(password: &[u8], salt: &[u8; BLOCK], level: u8) -> Self {
        let level = u32::from(level);
        let rounds = level * if level <= 15 { ROUNDS_LOW } else { ROUNDS_HIGH };
        let mut key = [0u8; KEY_LEN];
        // Upstream at level 0 runs the first round alone, which is what one round computes.
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, rounds.max(1), &mut key);
        Self(key)
    }

    /// Recovers the data key `KEY` and `KEY_INDEX` archives store, or `None` for a wrong password.
    pub(crate) fn unwrap(&self, iv: &[u8; BLOCK], wrapped: &[u8; WRAPPED_KEY_LEN]) -> Option<Self> {
        let mut plain = *wrapped;
        self.cbc(iv, &mut plain);
        (plain[KEY_LEN..] == *iv).then(|| {
            let mut key = [0u8; KEY_LEN];
            key.copy_from_slice(&plain[..KEY_LEN]);
            Self(key)
        })
    }

    /// Decrypts an encrypted blob and strips its padding.
    pub(crate) fn decrypt(&self, iv: &[u8; BLOCK], blob: &[u8]) -> Result<Vec<u8>, DecodeError> {
        ensure!(
            !blob.is_empty() && blob.len().is_multiple_of(BLOCK),
            decode_error::Decrypt {
                why: "it is not a whole number of AES blocks"
            }
        );
        let mut plain = blob.to_vec();
        self.cbc(iv, &mut plain);
        let len = unpadded_len(&plain).ok_or(DecodeError::Decrypt {
            why: "its padding is malformed, so the password is wrong or the blob corrupt",
        })?;
        plain.truncate(len);
        Ok(plain)
    }

    /// Decrypts whole blocks in place.
    fn cbc(&self, iv: &[u8; BLOCK], buf: &mut [u8]) {
        let mut mode = cbc::Decryptor::<Aes256>::new(&self.0.into(), &(*iv).into());
        for block in buf.as_chunks_mut::<BLOCK>().0 {
            mode.decrypt_block(block.into());
        }
    }
}

/// The length before PKCS#7 padding, checking every pad byte as upstream does.
fn unpadded_len(plain: &[u8]) -> Option<usize> {
    let &pad = plain.last()?;
    let pad_len = usize::from(pad);
    let valid = (1..=BLOCK).contains(&pad_len)
        && pad_len <= plain.len()
        && plain[plain.len() - pad_len..].iter().all(|&b| b == pad);
    valid.then(|| plain.len() - pad_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockModeEncrypt, KeyIvInit};
    use assert2::check;

    fn encrypt(key: &[u8; KEY_LEN], iv: &[u8; BLOCK], plain: &[u8]) -> Vec<u8> {
        let pad = BLOCK - plain.len() % BLOCK;
        let mut buf = plain.to_vec();
        buf.extend(std::iter::repeat_n(pad as u8, pad));
        let mut mode = cbc::Encryptor::<Aes256>::new(&(*key).into(), &(*iv).into());
        for block in buf.as_chunks_mut::<BLOCK>().0 {
            mode.encrypt_block(block.into());
        }
        buf
    }

    #[test]
    fn a_blob_round_trips_through_padding_of_every_length() {
        let key = Key([7; KEY_LEN]);
        for len in 0..=2 * BLOCK {
            let plain: Vec<u8> = (0..len as u8).collect();
            let blob = encrypt(&key.0, &[3; BLOCK], &plain);
            check!(key.decrypt(&[3; BLOCK], &blob).unwrap() == plain);
        }
    }

    #[test]
    fn a_wrong_key_fails_on_its_padding_or_its_length() {
        let blob = encrypt(&[7; KEY_LEN], &[3; BLOCK], b"some page bytes");
        let wrong = Key([8; KEY_LEN]);
        check!(let Err(DecodeError::Decrypt { .. }) = wrong.decrypt(&[3; BLOCK], &blob));
        check!(let Err(DecodeError::Decrypt { .. }) = wrong.decrypt(&[3; BLOCK], &blob[..15]));
        check!(let Err(DecodeError::Decrypt { .. }) = wrong.decrypt(&[3; BLOCK], &[]));
    }

    #[test]
    fn padding_is_checked_byte_for_byte() {
        let mut block = [0u8; BLOCK];
        block[13..].copy_from_slice(&[3, 3, 3]);
        check!(unpadded_len(&block) == Some(13));
        block[13] = 2;
        check!(unpadded_len(&block) == None);
        block[15] = 0;
        check!(unpadded_len(&block) == None);
        block[15] = 17;
        check!(unpadded_len(&block) == None);
    }

    #[test]
    fn a_stored_key_unwraps_only_under_the_password_that_wrapped_it() {
        let outer = Key([1; KEY_LEN]);
        let iv = [9; BLOCK];
        let mut inner = [5u8; WRAPPED_KEY_LEN];
        inner[KEY_LEN..].copy_from_slice(&iv);
        // The stored key is unpadded, so encrypt it block by block.
        let mut wrapped = inner;
        let mut mode = cbc::Encryptor::<Aes256>::new(&outer.0.into(), &iv.into());
        for block in wrapped.as_chunks_mut::<BLOCK>().0 {
            mode.encrypt_block(block.into());
        }
        check!(outer.unwrap(&iv, &wrapped).map(|k| k.0) == Some([5; KEY_LEN]));
        check!(Key([2; KEY_LEN]).unwrap(&iv, &wrapped).is_none());
    }
}
