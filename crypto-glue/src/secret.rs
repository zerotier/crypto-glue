/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::{convert::TryInto, ffi::c_void};

extern "C" {
    fn OPENSSL_cleanse(ptr: *mut c_void, len: usize);
}

/// Container for secrets that clears them on drop.
///
/// We can't be totally sure that things like libraries are doing this and it's
/// hard to get every use of a secret anywhere, but using this in our code at
/// least reduces the number of secrets that are left lying around in memory.
///
/// This is generally a low-risk thing since it's process memory that's protected,
/// but it's still not a bad idea due to things like swap or obscure side channel
/// attacks that allow memory to be read.
#[derive(Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct Secret<const L: usize>(pub [u8; L]);

impl<const L: usize> Secret<L> {
    /// Create a new all-zero secret.
    #[inline(always)]
    pub fn new() -> Self {
        Self([0_u8; L])
    }

    /// Moves bytes into secret, will panic if the slice does not match the size of this secret.
    #[inline(always)]
    pub fn move_bytes(b: [u8; L]) -> Self {
        Self(b)
    }

    /// Copy bytes into secret, then nuke the previous value, will panic if the slice does not match the size of this secret.
    #[inline(always)]
    pub fn from_bytes_then_nuke(b: &mut [u8]) -> Self {
        let ret = Self(b.try_into().unwrap());
        unsafe { OPENSSL_cleanse(b.as_mut_ptr().cast(), L) };
        ret
    }
    #[inline(always)]
    pub unsafe fn from_bytes(b: &[u8]) -> Self {
        Self(b.try_into().unwrap())
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8; L] {
        &self.0
    }
    #[inline(always)]
    pub fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    #[inline(always)]
    pub fn as_bytes_mut(&mut self) -> &mut [u8; L] {
        &mut self.0
    }

    /// Get the first N bytes of this secret as a fixed length array.
    #[inline(always)]
    pub fn first_n<const N: usize>(&self) -> &[u8; N] {
        assert!(N <= L);
        unsafe { &*self.0.as_ptr().cast() }
    }

    /// Clone the first N bytes of this secret as another secret.
    #[inline(always)]
    pub fn first_n_clone<const N: usize>(&self) -> Secret<N> {
        Secret::<N>(*self.first_n())
    }

    pub fn overwrite(&mut self, src: &Self) {
        self.0.copy_from_slice(&src.0);
    }
    pub fn overwrite_first_n<const N: usize>(&mut self, src: &Secret<N>) {
        let amount = N.min(L);
        self.0[..amount].copy_from_slice(&src.0[..amount]);
    }

    /// Destroy the contents of this secret, ignoring normal Rust mutability constraints.
    ///
    /// This can be used to force a secret to be forgotten under e.g. key lifetime exceeded or error conditions.
    #[inline(always)]
    pub fn nuke(&self) {
        unsafe { OPENSSL_cleanse(self.0.as_ptr().cast_mut().cast(), L) };
    }
}

impl<const L: usize> Drop for Secret<L> {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe { OPENSSL_cleanse(self.0.as_mut_ptr().cast(), L) };
    }
}

impl<const L: usize> Default for Secret<L> {
    #[inline(always)]
    fn default() -> Self {
        Self([0_u8; L])
    }
}

impl<const L: usize> AsRef<[u8]> for Secret<L> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const L: usize> AsRef<[u8; L]> for Secret<L> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8; L] {
        &self.0
    }
}

impl<const L: usize> AsMut<[u8]> for Secret<L> {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const L: usize> AsMut<[u8; L]> for Secret<L> {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8; L] {
        &mut self.0
    }
}
