/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::sync::Mutex;
use zssp::crypto_impl::openssl_sys::*;

use libc::c_int;
use once_cell::unsync::Lazy;
use zssp::crypto::rand_core::{CryptoRng, Error, RngCore, SeedableRng};

pub use zssp::crypto::rand_core;
/// This crate contains the most modern, feature rich and high-quality variants of the Xorshift family of random
/// number generators.
/// While they are not cryptographically secure, they are also faster and several times harder to
/// reverse than Xorshift64, so I think we should prefer them.
/// I read the source of this crate and it is low level and efficient.
pub use rand_xoshiro;
/// Xoshiro256** according to my benchmarking is surprisingly twice as fast as vanilla
/// Xorshift64 because there are fewer dependency chains in Xoshiro256** compared to Xorshift64.
pub use rand_xoshiro::Xoshiro256StarStar;

/// The cryptographically secure random number generator of OpenSSL.
#[derive(Default, Clone, Copy)]
pub struct SecureRandom;
impl SecureRandom {
    pub fn get_bytes<const SIZE: usize>(&mut self) -> [u8; SIZE] {
        let mut dest = [0u8; SIZE];
        self.fill_bytes(&mut dest);
        dest
    }
    /// Create an xorshift instance seeded with secure RNG.
    pub fn create_xorshift(&mut self) -> Xoshiro256StarStar {
        Xoshiro256StarStar::from_rng(self).unwrap()
    }
}
impl RngCore for SecureRandom {
    fn next_u32(&mut self) -> u32 {
        let mut tmp = [0u8; 4];
        self.fill_bytes(&mut tmp);
        u32::from_ne_bytes(tmp)
    }

    fn next_u64(&mut self) -> u64 {
        let mut tmp = [0u8; 8];
        self.fill_bytes(&mut tmp);
        u64::from_ne_bytes(tmp)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        unsafe {
            debug_assert!(dest.len() <= c_int::max_value() as usize);
            assert!(RAND_bytes(dest.as_mut_ptr(), dest.len() as c_int) > 0);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for SecureRandom {}
unsafe impl Sync for SecureRandom {}
unsafe impl Send for SecureRandom {}

/// A global Xoshiro256** wrapped in a mutex and a OnceCell.
/// Unsync OnceCell is just a wrapped `Option<>` and is very fast.
/// Also OnceCell is about to be stabilized into Rust std.
static GLOBAL_XORSHIFT: Mutex<Lazy<Xoshiro256StarStar>> = Mutex::new(Lazy::new(|| SecureRandom.create_xorshift()));

/// A non-cryptographically secure global random number generator.
pub struct XorshiftRandom;
impl XorshiftRandom {
    pub fn get_bytes<const COUNT: usize>(&mut self) -> [u8; COUNT] {
        let mut tmp = [0u8; COUNT];
        self.fill_bytes(&mut tmp);
        tmp
    }
    /// Create an xorshift instance seeded with the global xorshift RNG.
    pub fn create_xorshift(&mut self) -> Xoshiro256StarStar {
        let mut state = GLOBAL_XORSHIFT.lock().unwrap();
        let ret = state.clone();
        state.jump();
        ret
    }
}
impl RngCore for XorshiftRandom {
    fn next_u32(&mut self) -> u32 {
        GLOBAL_XORSHIFT.lock().unwrap().next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        GLOBAL_XORSHIFT.lock().unwrap().next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        GLOBAL_XORSHIFT.lock().unwrap().fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        GLOBAL_XORSHIFT.lock().unwrap().try_fill_bytes(dest)
    }
}
