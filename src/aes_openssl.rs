/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::ptr;

use zssp::crypto::*;
use zssp::crypto_impl::openssl_sys as ffi;

use zssp::crypto_impl::CipherCtx;

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
    pub fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self {
        let ctx = CipherCtx::new().unwrap();
        unsafe {
            let t = ffi::EVP_aes_256_gcm();
            assert!(ctx.cipher_init::<ENCRYPT>(t, key.as_ptr(), ptr::null()));
            ffi::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);
        }

        AesGcm(ctx)
    }

    /// Set the IV of this AesGcm context. This call resets the IV but leaves the key and encryption algorithm alone.
    /// This method must be called before any other method on AesGcm.
    /// `iv` must be exactly 12 bytes in length, because that is what Aes supports.
    pub fn reset_iv(&mut self, iv: &[u8]) {
        unsafe {
            assert!(self.0.cipher_init::<ENCRYPT>(ptr::null(), ptr::null(), iv.as_ptr()));
        }
    }

    /// Add additional authentication data to AesGcm (same operation with CTR mode).
    #[inline(always)]
    pub fn set_aad(&mut self, aad: &[u8]) {
        unsafe { assert!(self.0.update::<ENCRYPT>(aad, ptr::null_mut())) };
    }

    /// Encrypt or decrypt (same operation with CTR mode)
    #[inline(always)]
    pub fn crypt(&mut self, input: &[u8], output: &mut [u8]) {
        unsafe { assert!(self.0.update::<ENCRYPT>(input, output.as_mut_ptr())) };
    }

    /// Encrypt or decrypt in place (same operation with CTR mode).
    #[inline(always)]
    pub fn crypt_in_place(&mut self, data: &mut [u8]) {
        let ptr = data.as_mut_ptr();
        unsafe { assert!(self.0.update::<ENCRYPT>(data, ptr)) }
    }
}
impl AesGcm<true> {
    /// Produce the gcm authentication tag.
    #[inline(always)]
    pub fn finish_encrypt(&mut self, output: &mut [u8; AES_GCM_TAG_SIZE]) {
        unsafe {
            assert!(self.0.finalize::<true>());
            assert!(self.0.get_tag(output));
        }
    }
}
impl AesGcm<false> {
    /// Check the gcm authentication tag. Outputs true if it matches the just decrypted message, outputs false otherwise.
    #[inline(always)]
    pub fn finish_decrypt(&mut self, expected_tag: &[u8; AES_GCM_TAG_SIZE]) -> bool {
        unsafe { self.0.set_tag(expected_tag) && self.0.finalize::<false>() }
    }
}
