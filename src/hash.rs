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
pub const SHA384_HASH_SIZE: usize = 48;
pub const SHA256_HASH_SIZE: usize = 32;
pub const HMAC_SHA512_SIZE: usize = 64;
pub const HMAC_SHA384_SIZE: usize = 48;
pub const HMAC_SHA256_SIZE: usize = 32;

macro_rules! SHA_impl {
    ($tn:ident, $len:ident, $ctx:ident, $init:ident, $update:ident, $final:ident) => {
        pub struct $tn(ffi::$ctx);
        impl $tn {
            #[inline(always)]
            pub fn hash(data: &[u8]) -> [u8; $len] {
                unsafe {
                    let mut hash = MaybeUninit::<[u8; $len]>::uninit();
                    ffi::$tn(data.as_ptr(), data.len(), hash.as_mut_ptr() as *mut _);
                    hash.assume_init()
                }
            }

            /// Creates a new hasher.
            #[inline(always)]
            pub fn new() -> Self {
                unsafe {
                    let mut ctx = MaybeUninit::uninit();
                    ffi::$init(ctx.as_mut_ptr());
                    $tn(ctx.assume_init())
                }
            }

            #[inline(always)]
            pub fn reset(&mut self) {
                unsafe { ffi::$init(&mut self.0) };
            }

            /// Feeds some data into the hasher.
            ///
            /// This can be called multiple times.
            #[inline(always)]
            pub fn update(&mut self, buf: &[u8]) {
                unsafe {
                    ffi::$update(&mut self.0, buf.as_ptr() as *const c_void, buf.len());
                }
            }

            /// Returns the hash of the data.
            #[inline(always)]
            pub fn finish(&mut self) -> [u8; $len] {
                unsafe {
                    let mut hash = MaybeUninit::<[u8; $len]>::uninit();
                    ffi::$final(hash.as_mut_ptr() as *mut _, &mut self.0);
                    hash.assume_init()
                }
            }

            pub fn finish_into(&mut self, output: &mut [u8; $len]) {
                unsafe {
                    ffi::$final(output.as_mut_ptr() as *mut _, &mut self.0);
                }
            }
        }
        impl Write for $tn {
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
        unsafe impl Send for $tn {}
    };
}

SHA_impl!(
    SHA512,
    SHA512_HASH_SIZE,
    SHA512_CTX,
    SHA512_Init,
    SHA512_Update,
    SHA512_Final
);
SHA_impl!(
    SHA384,
    SHA384_HASH_SIZE,
    SHA512_CTX,
    SHA384_Init,
    SHA384_Update,
    SHA384_Final
);
SHA_impl!(
    SHA256,
    SHA256_HASH_SIZE,
    SHA256_CTX,
    SHA256_Init,
    SHA256_Update,
    SHA256_Final
);

macro_rules! impl_hmac {
    ($tn:ident, $evp:ident, $size:ident, $test:ident, $h1:literal, $h2:literal) => {
        cfg_if::cfg_if! {
            if #[cfg(stinkysll)] {
                pub struct $tn {
                    ctx: ffi::HMAC_CTX,
                    evp_md: *const ffi::EVP_MD,
                }
                impl $tn {
                    #[inline(always)]
                    pub fn new(key: &[u8]) -> Self {
                        unsafe {
                            let mut hm = Self { ctx: std::mem::zeroed(), evp_md: ffi::$evp() };
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
                            debug_assert_eq!(md.len(), $size);
                            let mut mdlen = $size as c_uint;
                            assert_ne!(ffi::HMAC_Final(&mut self.ctx, md.as_mut_ptr().cast(), &mut mdlen), 0);
                            debug_assert_eq!(mdlen, $size as c_uint);
                        }
                    }
                }
                impl Drop for $tn {
                    #[inline(always)]
                    fn drop(&mut self) {
                        unsafe { ffi::HMAC_CTX_cleanup(&mut self.ctx) };
                    }
                }
            } else {
                pub struct $tn {
                    ctx: *mut ffi::HMAC_CTX,
                    evp_md: *const ffi::EVP_MD,
                }
                impl $tn {
                    #[inline(always)]
                    pub fn new(key: &[u8]) -> Self {
                        unsafe {
                            let hm = Self { ctx: ffi::HMAC_CTX_new(), evp_md: ffi::$evp() };
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
                            debug_assert_eq!(md.len(), $size);
                            let mut mdlen = $size as c_uint;
                            assert_ne!(ffi::HMAC_Final(self.ctx, md.as_mut_ptr().cast(), &mut mdlen), 0);
                            debug_assert_eq!(mdlen, $size as c_uint);
                        }
                    }
                }
                impl Drop for $tn {
                    #[inline(always)]
                    fn drop(&mut self) {
                        unsafe { ffi::HMAC_CTX_free(self.ctx) };
                    }
                }
            }
        }
        impl $tn {
            #[inline(always)]
            pub fn finish(&mut self) -> [u8; $size] {
                let mut tmp = [0u8; $size];
                self.finish_into(&mut tmp);
                tmp
            }
        }
        unsafe impl Send for $tn {}


        #[test]
        fn $test() {
            let mut hmac = $tn::new(b"test_key");
            hmac.update(b"hello");
            hmac.update(b" ");
            hmac.update(b"world");
            assert_eq!(hmac.finish(), hex_literal::hex!($h1));
            hmac.reset(b"new test key very long 1234567890123456789012345678901234567890");
            hmac.update(b"hello");
            hmac.update(b" ");
            hmac.update(b"world");
            assert_eq!(hmac.finish(), hex_literal::hex!($h2));
        }
    }
}

impl_hmac!(
    HMACSHA256,
    EVP_sha256,
    HMAC_SHA256_SIZE,
    test_hmac_sha_256,
    "6dbc39caf10e76cd731f67c314dfb3f412221e663be0dd766dd98b7e3bd1ac52",
    "57aaad989a15911c90f3364e5af88e1b003f679c24739b0e89c5dd1dd5f04f0d"
);
impl_hmac!(
    HMACSHA384,
    EVP_sha384,
    HMAC_SHA384_SIZE,
    test_hmac_sha_384,
    "587de0242c327f4641eb04a236234890fd78b13a41588e4014fe4f15b6cbcfd16151a86d16bc9caec79a1b0bdef4e513",
    "fcc9042dea7b19c313d7d9943d2a9a65062d0a78225878eed7e78ca8eb11bd00ab02981a21cabd43d459f42b179f5c28"
);
impl_hmac!(HMACSHA512, EVP_sha512, HMAC_SHA512_SIZE, test_hmac_sha_512, "bb1c44405a097766cfca923828d1b9c46f1cdfb357ce1d21534c2a629f59f533a356a13f2250c6636b0c9cce78a1668cc8219cdeef9407cfe61de1713b130ea8", "6ff2e38e644e5f1e012f74fe8cc4e59505f668c500e5a7eea42e3a01ed9f093386e5786ffb1c5166deb5995bddd2c4e51a7e99b907fbe22fe07e1eff1f081473");

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
