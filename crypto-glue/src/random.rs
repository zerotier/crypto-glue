/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::sync::Mutex;

use libc::c_int;
use once_cell::unsync::Lazy;
use rand_xoshiro::rand_core::{CryptoRng, Error, RngCore, SeedableRng};

use crate::error::cvt;

/// Fill buffer with cryptographically strong pseudo-random bytes.
#[inline]
pub fn fill_bytes_secure(dest: &mut [u8]) {
    unsafe {
        debug_assert!(dest.len() <= c_int::max_value() as usize);
        cvt(ffi::RAND_bytes(dest.as_mut_ptr(), dest.len() as c_int)).unwrap();
    }
}

pub fn next_u32_secure() -> u32 {
    let mut tmp = [0u8; 4];
    fill_bytes_secure(&mut tmp);
    u32::from_ne_bytes(tmp)
}

pub fn next_u64_secure() -> u64 {
    let mut tmp = [0u8; 8];
    fill_bytes_secure(&mut tmp);
    u64::from_ne_bytes(tmp)
}

pub fn next_u128_secure() -> u128 {
    let mut tmp = [0u8; 16];
    fill_bytes_secure(&mut tmp);
    u128::from_ne_bytes(tmp)
}

#[inline(always)]
pub fn get_bytes_secure<const COUNT: usize>() -> [u8; COUNT] {
    let mut tmp = [0u8; COUNT];
    fill_bytes_secure(&mut tmp);
    tmp
}

pub struct SecureRandom;

impl Default for SecureRandom {
    #[inline(always)]
    fn default() -> Self {
        Self
    }
}

impl SecureRandom {
    #[inline(always)]
    pub fn get() -> Self {
        Self
    }
}

impl RngCore for SecureRandom {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        next_u32_secure()
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        next_u64_secure()
    }

    #[inline(always)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_bytes_secure(dest);
    }

    #[inline(always)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        fill_bytes_secure(dest);
        Ok(())
    }
}

/// ed25519-dalek still uses rand_core 0.5.1, and that version is incompatible with 0.6.4, so we need to import and implement both.
impl rand_core_051::RngCore for SecureRandom {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        next_u32_secure()
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        next_u64_secure()
    }

    #[inline(always)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_bytes_secure(dest);
    }

    #[inline(always)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_051::Error> {
        fill_bytes_secure(dest);
        Ok(())
    }
}

impl CryptoRng for SecureRandom {}
impl rand_core_051::CryptoRng for SecureRandom {}
unsafe impl Sync for SecureRandom {}
unsafe impl Send for SecureRandom {}

/// This crate contains the most modern, feature rich and high-quality variants of the Xorshift family of random
/// number generators.
/// While they are not cryptographically secure, they are also faster and several times harder to
/// reverse than Xorshift64, so I think we should prefer them.
/// I read the source of this crate and it is low level and efficient.
pub use rand_xoshiro;
/// Xoshiro256** according to my benchmarking is surprisingly twice as fast as vanilla
/// Xorshift64 because there are fewer dependency chains in Xoshiro256** compared to Xorshift64.
pub use rand_xoshiro::Xoshiro256StarStar;

/// A global Xoshiro256** wrapped in a mutex and a OnceCell.
/// Unsync OnceCell is just a wrapped `Option<>` and is very fast.
/// Also OnceCell is about to be stabilized into Rust std.
pub static GLOBAL_XORSHIFT: Mutex<Lazy<Xoshiro256StarStar>> =
    Mutex::new(Lazy::new(|| Xoshiro256StarStar::from_rng(SecureRandom).unwrap()));

/// Quickly creates a new Xoshiro256StarStar state that is randomly seeded and fully owned by the
/// caller (does not require dereferencing and locking a global variable).
#[inline]
pub fn new_xorshift_rng() -> Xoshiro256StarStar {
    let mut state = GLOBAL_XORSHIFT.lock().unwrap();
    let ret = state.clone();
    state.jump();
    ret
}
/// Generate a random 64-bit number (not cryptographically secure).
#[inline]
pub fn next_u64_xorshift() -> u64 {
    GLOBAL_XORSHIFT.lock().unwrap().next_u64()
}

/// Generate a random 32-bit number (not cryptographically secure).
#[inline]
pub fn next_u32_xorshift() -> u32 {
    GLOBAL_XORSHIFT.lock().unwrap().next_u32()
}
