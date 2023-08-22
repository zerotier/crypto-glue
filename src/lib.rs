/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

//mod error;
mod aes_tests;

pub mod hash;
pub mod p384;
pub mod random;

pub mod poly1305;
pub mod salsa;
pub mod typestate;
pub mod x25519;

// TODO: Bring back the faster Apple API implementations.

pub mod aes_openssl;

pub use aes_openssl as aes;

pub mod aes_gmac_siv_openssl;
pub use aes_gmac_siv_openssl as aes_gmac_siv;

/// Dependency re-export
pub use zssp;

#[macro_export]
macro_rules! impl_zssp_crypto {
    ($t:ty, $session_data:ty, $packet_buffer:ty) => {
        impl zssp::application::CryptoLayer for $t {
            type Rng = crate::random::SecureRandom;

            type PrpEnc = zssp::crypto_impl::OpenSSLAes256Enc;
            type PrpDec = zssp::crypto_impl::OpenSSLAes256Dec;

            type Aead = zssp::crypto_impl::OpenSSLAesGcm;
            type AeadPool = zssp::crypto_impl::OpenSSLAesGcmPool;

            type Hash = crate::hash::SHA512;
            type Hmac = crate::hash::HMACSHA512;

            type PublicKey = crate::p384::P384PublicKey;
            type KeyPair = crate::p384::P384KeyPair;
            type Kem = zssp::crypto_impl::CrateKyber1024PrivateKey;

            type SessionData = $session_data;
            type IncomingPacketBuffer = $packet_buffer;
        }
    }
}

use ctor::ctor;
#[ctor]
fn openssl_init() {
    zssp::crypto_impl::openssl_sys::init();
}

/// Constant time byte slice equality.
#[inline]
pub fn secure_eq<A: AsRef<[u8]> + ?Sized, B: AsRef<[u8]> + ?Sized>(a: &A, b: &B) -> bool {
    let (a, b) = (a.as_ref(), b.as_ref());
    if a.len() == b.len() {
        let mut x = 0u8;
        for (aa, bb) in a.iter().zip(b.iter()) {
            x |= *aa ^ *bb;
        }
        x == 0
    } else {
        false
    }
}

pub const ZEROES: [u8; 64] = [0_u8; 64];
