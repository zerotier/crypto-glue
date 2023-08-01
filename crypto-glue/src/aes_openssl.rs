/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::{ptr, sync::Mutex};

use zssp::crypto::{aes, aes_gcm};

use crate::cipher_ctx::CipherCtx;

/// An OpenSSL AES_GCM context. Automatically frees itself on drop.
/// The current interface is custom made for ZeroTier, but could easily be adapted for other uses.
/// Whether `ENCRYPT` is true or false decides respectively whether this context encrypts or decrypts.
/// Even though OpenSSL lets you set this dynamically almost no operations work when you do this
/// without resetting the context.
///
/// This object cannot be mutated by multiple threads at the same time so wrap it in a Mutex if
/// you need to do this. As far as I have read a Mutex<AesGcm> can safely implement Send and Sync.
pub struct AesGcm<const ENCRYPT: bool>(CipherCtx);

impl<const ENCRYPT: bool> AesGcm<ENCRYPT> {
    /// Create an AesGcm context with the given key.
    /// OpenSSL internally processes and caches this key, so it is recommended to reuse this context whenever encrypting under the same key. Call `reset_init_gcm` to change the IV for each reuse.
    fn new(key: &[u8; aes_gcm::AES_GCM_KEY_SIZE]) -> Self {
        let ctx = CipherCtx::new().unwrap();
        unsafe {
            let t = ffi::EVP_aes_256_gcm();
            ctx.cipher_init::<ENCRYPT>(t, key.as_ptr(), ptr::null()).unwrap();
            ffi::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);
        }

        AesGcm(ctx)
    }

    /// Set the IV of this AesGcm context. This call resets the IV but leaves the key and encryption algorithm alone.
    /// This method must be called before any other method on AesGcm.
    /// `iv` must be exactly 12 bytes in length, because that is what Aes supports.
    fn reset_init_gcm(&mut self, iv: &[u8]) {
        unsafe {
            self.0.cipher_init::<ENCRYPT>(ptr::null(), ptr::null(), iv.as_ptr()).unwrap();
        }
    }

    /// Add additional authentication data to AesGcm (same operation with CTR mode).
    #[inline(always)]
    fn aad(&mut self, aad: &[u8]) {
        unsafe { self.0.update::<ENCRYPT>(aad, ptr::null_mut()).unwrap() };
    }

    /// Encrypt or decrypt (same operation with CTR mode)
    #[inline(always)]
    fn crypt(&mut self, input: &[u8], output: &mut [u8]) {
        unsafe { self.0.update::<ENCRYPT>(input, output.as_mut_ptr()).unwrap() };
    }

    /// Encrypt or decrypt in place (same operation with CTR mode).
    #[inline(always)]
    fn crypt_in_place(&mut self, data: &mut [u8]) {
        let ptr = data.as_mut_ptr();
        unsafe { self.0.update::<ENCRYPT>(data, ptr).unwrap() }
    }
}
impl AesGcm<true> {
    /// Produce the gcm authentication tag.
    #[inline(always)]
    fn finish_encrypt(&mut self, output: &mut [u8; aes_gcm::AES_GCM_TAG_SIZE]) {
        unsafe {
            self.0.finalize::<true>().unwrap();
            self.0.tag(output).unwrap();
        }
    }
}
impl AesGcm<false> {
    /// Check the gcm authentication tag. Outputs true if it matches the just decrypted message, outputs false otherwise.
    #[inline(always)]
    fn finish_decrypt(&mut self, expected_tag: &[u8; aes_gcm::AES_GCM_TAG_SIZE]) -> bool {
        unsafe { self.0.set_tag(expected_tag).is_ok() && self.0.finalize::<false>().is_ok() }
    }
}

impl aes_gcm::AesGcmEnc for AesGcm<true> {
    fn new(key: &[u8; aes_gcm::AES_GCM_KEY_SIZE]) -> Self {
        Self::new(key)
    }
    fn set_iv(&mut self, iv: &[u8; aes_gcm::AES_GCM_IV_SIZE]) {
        self.reset_init_gcm(iv)
    }
    fn set_aad(&mut self, aad: &[u8]) {
        self.aad(aad)
    }
    fn encrypt(&mut self, input: &[u8], output: &mut [u8]) {
        self.crypt(input, output)
    }
    fn encrypt_in_place(&mut self, data: &mut [u8]) {
        self.crypt_in_place(data)
    }
    fn finish_encrypt(&mut self, output: &mut [u8; aes_gcm::AES_GCM_TAG_SIZE]) {
        self.finish_encrypt(output)
    }
}
impl aes_gcm::AesGcmDec for AesGcm<false> {
    fn new(key: &[u8; aes_gcm::AES_GCM_KEY_SIZE]) -> Self {
        Self::new(key)
    }
    fn set_iv(&mut self, iv: &[u8; aes_gcm::AES_GCM_IV_SIZE]) {
        self.reset_init_gcm(iv)
    }
    fn set_aad(&mut self, aad: &[u8]) {
        self.aad(aad)
    }
    fn decrypt(&mut self, input: &[u8], output: &mut [u8]) {
        self.crypt(input, output)
    }
    fn decrypt_in_place(&mut self, data: &mut [u8]) {
        self.crypt_in_place(data)
    }
    fn finish_decrypt(&mut self, expected_tag: &[u8; aes_gcm::AES_GCM_TAG_SIZE]) -> bool {
        self.finish_decrypt(expected_tag)
    }
}

/// An OpenSSL AES_ECB context. Automatically frees itself on drop.
/// AES_ECB is very insecure if used incorrectly so its public interface supports only exactly what
/// ZeroTier uses it for.
pub struct Aes<const ENCRYPT: bool>(Mutex<CipherCtx>);
unsafe impl<const ENCRYPT: bool> Send for Aes<ENCRYPT> {}
unsafe impl<const ENCRYPT: bool> Sync for Aes<ENCRYPT> {}

impl<const ENCRYPT: bool> Aes<ENCRYPT> {
    fn new(key: &[u8; aes::AES_256_KEY_SIZE]) -> Self {
        let ctx = CipherCtx::new().unwrap();
        unsafe {
            let t = ffi::EVP_aes_256_ecb();
            ctx.cipher_init::<ENCRYPT>(t, key.as_ptr(), ptr::null()).unwrap();
            ffi::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);
        }

        Aes(Mutex::new(ctx))
    }

    fn reset(&self, key: &[u8; aes::AES_256_KEY_SIZE]) {
        let ctx = self.0.lock().unwrap();
        unsafe {
            ctx.cipher_init::<ENCRYPT>(ptr::null(), key.as_ptr(), ptr::null()).unwrap();
        }
    }
}

impl aes::AesEnc for Aes<true> {
    fn new(key: &[u8; aes::AES_256_KEY_SIZE]) -> Self {
        Self::new(key)
    }
    fn reset(&self, key: &[u8; aes::AES_256_KEY_SIZE]) {
        self.reset(key)
    }

    fn encrypt_in_place(&self, block: &mut [u8; aes::AES_256_BLOCK_SIZE]) {
        let ptr = block.as_mut_ptr();
        let ctx = self.0.lock().unwrap();
        unsafe { ctx.update::<true>(block, ptr).unwrap() }
    }
}
impl aes::AesDec for Aes<false> {
    fn new(key: &[u8; aes::AES_256_KEY_SIZE]) -> Self {
        Self::new(key)
    }
    fn reset(&self, key: &[u8; aes::AES_256_KEY_SIZE]) {
        self.reset(key)
    }

    fn decrypt_in_place(&self, block: &mut [u8; aes::AES_256_BLOCK_SIZE]) {
        let ptr = block.as_mut_ptr();
        let ctx = self.0.lock().unwrap();
        unsafe { ctx.update::<false>(block, ptr).unwrap() }
    }
}
