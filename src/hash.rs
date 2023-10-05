/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::ffi::c_void;
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::raw::{c_int, c_uint};
use std::ptr::null_mut;

use zssp::crypto::{Sha512Hash, Sha512Hmac};
use zssp::crypto_impl::openssl_sys as ffi;

pub const SHA512_HASH_SIZE: usize = 64;
pub const HMAC_SHA512_SIZE: usize = 64;
pub const SHA384_HASH_SIZE: usize = 48;
pub const HMAC_SHA384_SIZE: usize = 48;

pub struct SHA512(ffi::SHA512_CTX);
impl SHA512 {
    #[inline(always)]
    pub fn hash(data: &[u8]) -> [u8; SHA512_HASH_SIZE] {
        unsafe {
            let mut hash = MaybeUninit::<[u8; SHA512_HASH_SIZE]>::uninit();
            ffi::SHA512(data.as_ptr(), data.len(), hash.as_mut_ptr() as *mut _);
            hash.assume_init()
        }
    }

    /// Creates a new hasher.
    #[inline(always)]
    pub fn new() -> Self {
        unsafe {
            let mut ctx = MaybeUninit::uninit();
            ffi::SHA512_Init(ctx.as_mut_ptr());
            SHA512(ctx.assume_init())
        }
    }

    #[inline(always)]
    pub fn reset(&mut self) {
        unsafe { ffi::SHA512_Init(&mut self.0) };
    }

    /// Feeds some data into the hasher.
    ///
    /// This can be called multiple times.
    #[inline(always)]
    pub fn update(&mut self, buf: &[u8]) {
        unsafe {
            ffi::SHA512_Update(&mut self.0, buf.as_ptr() as *const c_void, buf.len());
        }
    }

    /// Returns the hash of the data.
    #[inline(always)]
    pub fn finish(&mut self) -> [u8; SHA512_HASH_SIZE] {
        unsafe {
            let mut hash = MaybeUninit::<[u8; SHA512_HASH_SIZE]>::uninit();
            ffi::SHA512_Final(hash.as_mut_ptr() as *mut _, &mut self.0);
            hash.assume_init()
        }
    }

    pub fn finish_into(&mut self, output: &mut [u8; SHA512_HASH_SIZE]) {
        unsafe {
            ffi::SHA512_Final(output.as_mut_ptr() as *mut _, &mut self.0);
        }
    }
}
impl Write for SHA512 {
    #[inline(always)]
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.update(b);
        Ok(b.len())
    }

    #[inline(always)]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
unsafe impl Send for SHA512 {}

pub struct SHA384(ffi::SHA512_CTX);
impl SHA384 {
    #[inline(always)]
    pub fn hash(data: &[u8]) -> [u8; SHA384_HASH_SIZE] {
        unsafe {
            let mut hash = MaybeUninit::<[u8; SHA384_HASH_SIZE]>::uninit();
            ffi::SHA384(data.as_ptr(), data.len(), hash.as_mut_ptr() as *mut _);
            hash.assume_init()
        }
    }

    #[inline(always)]
    pub fn new() -> Self {
        unsafe {
            let mut ctx = MaybeUninit::uninit();
            ffi::SHA384_Init(ctx.as_mut_ptr());
            SHA384(ctx.assume_init())
        }
    }

    #[inline(always)]
    pub fn reset(&mut self) {
        unsafe {
            ffi::SHA384_Init(&mut self.0);
        }
    }

    #[inline(always)]
    pub fn update(&mut self, buf: &[u8]) {
        unsafe {
            ffi::SHA384_Update(&mut self.0, buf.as_ptr() as *const c_void, buf.len());
        }
    }

    #[inline(always)]
    pub fn finish(&mut self) -> [u8; SHA384_HASH_SIZE] {
        unsafe {
            let mut hash = MaybeUninit::<[u8; SHA384_HASH_SIZE]>::uninit();
            ffi::SHA384_Final(hash.as_mut_ptr() as *mut _, &mut self.0);
            hash.assume_init()
        }
    }

    #[inline(always)]
    pub fn finish_into(&mut self, output: &mut [u8; SHA512_HASH_SIZE]) {
        unsafe {
            ffi::SHA384_Final(output.as_mut_ptr() as *mut _, &mut self.0);
        }
    }
}
impl Write for SHA384 {
    #[inline(always)]
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.update(b);
        Ok(b.len())
    }

    #[inline(always)]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
unsafe impl Send for SHA384 {}

cfg_if::cfg_if! {
    if #[cfg(stinkysll)] {
        pub struct HMACSHA512 {
            ctx: ffi::HMAC_CTX,
            evp_md: *const ffi::EVP_MD,
        }
        impl HMACSHA512 {
            #[inline(always)]
            pub fn new(key: &[u8]) -> Self {
                unsafe {
                    let mut hm = Self { ctx: std::mem::zeroed(), evp_md: ffi::EVP_sha512() };
                    ffi::HMAC_CTX_init(&mut hm.ctx);
                    hm.reset(key);
                    hm
                }
            }

            #[inline(always)]
            pub fn reset(&mut self, key: &[u8]) {
                unsafe {
                    assert_ne!(
                        ffi::HMAC_Init_ex(&mut self.ctx, key.as_ptr().cast(), key.len() as c_int, self.evp_md, null_mut()),
                        0
                    );
                }
            }
            #[inline(always)]
            pub fn update(&mut self, b: &[u8]) {
                unsafe {
                    assert_ne!(ffi::HMAC_Update(&mut self.ctx, b.as_ptr().cast(), b.len()), 0);
                }
            }

            #[inline(always)]
            pub fn finish_into(&mut self, md: &mut [u8]) {
                unsafe {
                    debug_assert_eq!(md.len(), HMAC_SHA512_SIZE);
                    let mut mdlen = HMAC_SHA512_SIZE as c_uint;
                    assert_ne!(ffi::HMAC_Final(&mut self.ctx, md.as_mut_ptr().cast(), &mut mdlen), 0);
                    debug_assert_eq!(mdlen, HMAC_SHA512_SIZE as c_uint);
                }
            }
        }
        impl Drop for HMACSHA512 {
            #[inline(always)]
            fn drop(&mut self) {
                unsafe { ffi::HMAC_CTX_cleanup(&mut self.ctx) };
            }
        }
    } else {
        pub struct HMACSHA512 {
            ctx: *mut ffi::HMAC_CTX,
            evp_md: *const ffi::EVP_MD,
        }
        impl HMACSHA512 {
            #[inline(always)]
            pub fn new(key: &[u8]) -> Self {
                unsafe {
                    let hm = Self { ctx: ffi::HMAC_CTX_new(), evp_md: ffi::EVP_sha512() };
                    assert!(!hm.ctx.is_null());
                    assert_ne!(
                        ffi::HMAC_Init_ex(hm.ctx, key.as_ptr().cast(), key.len() as c_int, hm.evp_md, null_mut()),
                        0
                    );
                    hm
                }
            }

            #[inline(always)]
            pub fn reset(&mut self, key: &[u8]) {
                unsafe {
                    assert_ne!(
                        ffi::HMAC_Init_ex(self.ctx, key.as_ptr().cast(), key.len() as c_int, self.evp_md, null_mut()),
                        0
                    );
                }
            }
            #[inline(always)]
            pub fn update(&mut self, b: &[u8]) {
                unsafe {
                    assert_ne!(ffi::HMAC_Update(self.ctx, b.as_ptr().cast(), b.len()), 0);
                }
            }

            #[inline(always)]
            pub fn finish_into(&mut self, md: &mut [u8]) {
                unsafe {
                    debug_assert_eq!(md.len(), HMAC_SHA512_SIZE);
                    let mut mdlen = HMAC_SHA512_SIZE as c_uint;
                    assert_ne!(ffi::HMAC_Final(self.ctx, md.as_mut_ptr().cast(), &mut mdlen), 0);
                    debug_assert_eq!(mdlen, HMAC_SHA512_SIZE as c_uint);
                }
            }
        }
        impl Drop for HMACSHA512 {
            #[inline(always)]
            fn drop(&mut self) {
                unsafe { ffi::HMAC_CTX_free(self.ctx) };
            }
        }
    }
}
impl HMACSHA512 {
    #[inline(always)]
    pub fn finish(&mut self) -> [u8; HMAC_SHA512_SIZE] {
        let mut tmp = [0u8; HMAC_SHA512_SIZE];
        self.finish_into(&mut tmp);
        tmp
    }
}
unsafe impl Send for HMACSHA512 {}

/* Start of ZSSP Impl */

impl Sha512Hmac for HMACSHA512 {
    fn new() -> Self {
        HMACSHA512::new(&[])
    }

    fn hash(&mut self, key: &[u8], full_input: &[u8], output: &mut [u8; SHA512_HASH_SIZE]) {
        self.reset(key);
        self.update(full_input);
        self.finish_into(output);
    }
}

impl Sha512Hash for SHA512 {
    fn new() -> Self {
        SHA512::new()
    }

    fn update(&mut self, data: &[u8]) {
        self.update(data);
    }

    fn finish_and_reset(&mut self, output: &mut [u8; SHA512_HASH_SIZE]) {
        self.finish_into(output);
        self.reset();
    }
}
