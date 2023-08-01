/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::ptr;

use crate::{cipher_ctx::CipherCtx, ZEROES};

/// AES-GMAC-SIV encryptor/decryptor.
pub struct AesGmacSiv {
    tag: [u8; 16],
    tmp: [u8; 16],
    ecb_enc: CipherCtx,
    ecb_dec: CipherCtx,
    ctr: CipherCtx,
    gmac: CipherCtx,
}

impl AesGmacSiv {
    /// Create a new keyed instance of AES-GMAC-SIV
    /// The key may be of size 16, 24, or 32 bytes (128, 192, or 256 bits). Any other size will panic.
    pub fn new(k0: &[u8], k1: &[u8]) -> Self {
        let gmac = CipherCtx::new().unwrap();
        unsafe {
            let t = match k0.len() {
                16 => ffi::EVP_aes_128_gcm(),
                24 => ffi::EVP_aes_192_gcm(),
                32 => ffi::EVP_aes_256_gcm(),
                _ => panic!("Aes KEY_SIZE must be 16, 24 or 32"),
            };
            gmac.cipher_init::<true>(t, k0.as_ptr(), ptr::null_mut()).unwrap();
        }
        let ctr = CipherCtx::new().unwrap();
        unsafe {
            let t = match k1.len() {
                16 => ffi::EVP_aes_128_ctr(),
                24 => ffi::EVP_aes_192_ctr(),
                32 => ffi::EVP_aes_256_ctr(),
                _ => panic!("Aes KEY_SIZE must be 16, 24 or 32"),
            };
            ctr.cipher_init::<true>(t, k1.as_ptr(), ptr::null_mut()).unwrap();
        }
        let ecb_enc = CipherCtx::new().unwrap();
        unsafe {
            let t = match k1.len() {
                16 => ffi::EVP_aes_128_ecb(),
                24 => ffi::EVP_aes_192_ecb(),
                32 => ffi::EVP_aes_256_ecb(),
                _ => panic!("Aes KEY_SIZE must be 16, 24 or 32"),
            };
            ecb_enc.cipher_init::<true>(t, k1.as_ptr(), ptr::null_mut()).unwrap();
            ffi::EVP_CIPHER_CTX_set_padding(ecb_enc.as_ptr(), 0);
        }
        let ecb_dec = CipherCtx::new().unwrap();
        unsafe {
            let t = match k1.len() {
                16 => ffi::EVP_aes_128_ecb(),
                24 => ffi::EVP_aes_192_ecb(),
                32 => ffi::EVP_aes_256_ecb(),
                _ => panic!("Aes KEY_SIZE must be 16, 24 or 32"),
            };
            ecb_dec.cipher_init::<false>(t, k1.as_ptr(), ptr::null_mut()).unwrap();
            ffi::EVP_CIPHER_CTX_set_padding(ecb_dec.as_ptr(), 0);
        }

        AesGmacSiv {
            tag: [0_u8; 16],
            tmp: [0_u8; 16],
            ecb_dec,
            ecb_enc,
            ctr,
            gmac,
        }
    }

    /// Reset to prepare for another encrypt or decrypt operation.
    #[inline(always)]
    pub fn reset(&mut self) {}

    /// Initialize for encryption.
    #[inline(always)]
    pub fn encrypt_init(&mut self, iv: &[u8]) {
        self.tag[0..8].copy_from_slice(iv);
        self.tag[8..12].fill(0);
        unsafe {
            self.gmac
                .cipher_init::<true>(ptr::null_mut(), ptr::null_mut(), self.tag[0..12].as_ptr())
                .unwrap();
        }
    }

    /// Set additional authenticated data (data to be authenticated but not encrypted).
    /// This can currently only be called once. Multiple calls will result in corrupt data.
    #[inline(always)]
    pub fn encrypt_set_aad(&mut self, data: &[u8]) {
        unsafe {
            self.gmac.update::<true>(data, ptr::null_mut()).unwrap();
            let mut pad = data.len() & 0xf;
            if pad != 0 {
                pad = 16 - pad;
                self.gmac.update::<true>(&ZEROES[0..pad], ptr::null_mut()).unwrap();
            }
        }
    }

    /// Feed plaintext in for the first encryption pass.
    /// This may be called more than once.
    #[inline(always)]
    pub fn encrypt_first_pass(&mut self, plaintext: &[u8]) {
        unsafe {
            self.gmac.update::<true>(plaintext, ptr::null_mut()).unwrap();
        }
    }

    /// Finish first pass and begin second pass.
    #[inline(always)]
    pub fn encrypt_first_pass_finish(&mut self) {
        unsafe {
            self.gmac.finalize::<true>().unwrap();
            self.gmac.tag(&mut self.tmp).unwrap();
        }

        self.tag[8] = self.tmp[0] ^ self.tmp[8];
        self.tag[9] = self.tmp[1] ^ self.tmp[9];
        self.tag[10] = self.tmp[2] ^ self.tmp[10];
        self.tag[11] = self.tmp[3] ^ self.tmp[11];
        self.tag[12] = self.tmp[4] ^ self.tmp[12];
        self.tag[13] = self.tmp[5] ^ self.tmp[13];
        self.tag[14] = self.tmp[6] ^ self.tmp[14];
        self.tag[15] = self.tmp[7] ^ self.tmp[15];

        let mut tag_tmp = [0_u8; 16];

        unsafe {
            self.ecb_enc.update::<true>(&self.tag, tag_tmp.as_mut_ptr()).unwrap();
        }
        self.tag.copy_from_slice(&tag_tmp);
        self.tmp.copy_from_slice(&tag_tmp);

        self.tmp[12] &= 0x7f;

        unsafe {
            self.ctr.cipher_init::<true>(ptr::null_mut(), ptr::null_mut(), self.tmp.as_ptr()).unwrap();
        }
    }

    /// Feed plaintext for second pass and write ciphertext to supplied buffer.
    /// This may be called more than once.
    #[inline(always)]
    pub fn encrypt_second_pass(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) {
        unsafe {
            self.ctr.update::<true>(plaintext, ciphertext.as_mut_ptr()).unwrap();
        }
    }

    /// Encrypt plaintext in place.
    /// This may be called more than once.
    #[inline(always)]
    pub fn encrypt_second_pass_in_place(&mut self, plaintext_to_ciphertext: &mut [u8]) {
        unsafe {
            let out = plaintext_to_ciphertext.as_mut_ptr();
            self.ctr.update::<true>(plaintext_to_ciphertext, out).unwrap();
        }
    }

    /// Finish second pass and return a reference to the tag for this message.
    /// The tag returned remains valid until reset() is called.
    #[inline(always)]
    pub fn encrypt_second_pass_finish(&mut self) -> &[u8; 16] {
        &self.tag
    }

    /// Initialize this cipher for decryption.
    /// The supplied tag must be 16 bytes in length. Any other length will panic.
    #[inline(always)]
    pub fn decrypt_init(&mut self, tag: &[u8]) {
        self.tmp.copy_from_slice(tag);
        self.tmp[12] &= 0x7f;

        unsafe {
            self.ctr
                .cipher_init::<false>(ptr::null_mut(), ptr::null_mut(), self.tmp.as_ptr())
                .unwrap();
        }

        let mut tag_tmp = [0_u8; 16];

        unsafe {
            self.ecb_dec.update::<false>(tag, tag_tmp.as_mut_ptr()).unwrap();
        }
        self.tag.copy_from_slice(&tag_tmp);
        tag_tmp[8..12].fill(0);

        unsafe {
            self.gmac.cipher_init::<true>(ptr::null_mut(), ptr::null_mut(), tag_tmp.as_ptr()).unwrap();
        }
    }

    /// Set additional authenticated data to be checked.
    #[inline(always)]
    pub fn decrypt_set_aad(&mut self, data: &[u8]) {
        self.encrypt_set_aad(data);
    }

    /// Decrypt ciphertext and write to plaintext.
    /// This may be called more than once.
    #[inline(always)]
    pub fn decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) {
        unsafe {
            self.ctr.update::<false>(ciphertext, plaintext.as_mut_ptr()).unwrap();
            self.gmac.update::<true>(plaintext, ptr::null_mut()).unwrap();
        }
    }

    /// Decrypt ciphertext in place.
    /// This may be called more than once.
    #[inline(always)]
    pub fn decrypt_in_place(&mut self, ciphertext_to_plaintext: &mut [u8]) {
        self.decrypt(
            unsafe { std::slice::from_raw_parts(ciphertext_to_plaintext.as_ptr(), ciphertext_to_plaintext.len()) },
            ciphertext_to_plaintext,
        );
    }

    /// Finish decryption and return true if authentication appears valid.
    /// If this returns false the message should be dropped.
    #[inline(always)]
    pub fn decrypt_finish(&mut self) -> Option<&[u8; 16]> {
        unsafe {
            self.gmac.finalize::<true>().unwrap();
            self.gmac.tag(&mut self.tmp).unwrap();
        }
        if (self.tag[8] == self.tmp[0] ^ self.tmp[8])
            && (self.tag[9] == self.tmp[1] ^ self.tmp[9])
            && (self.tag[10] == self.tmp[2] ^ self.tmp[10])
            && (self.tag[11] == self.tmp[3] ^ self.tmp[11])
            && (self.tag[12] == self.tmp[4] ^ self.tmp[12])
            && (self.tag[13] == self.tmp[5] ^ self.tmp[13])
            && (self.tag[14] == self.tmp[6] ^ self.tmp[14])
            && (self.tag[15] == self.tmp[7] ^ self.tmp[15])
        {
            Some(&self.tag)
        } else {
            None
        }
    }
}

unsafe impl Send for AesGmacSiv {}
