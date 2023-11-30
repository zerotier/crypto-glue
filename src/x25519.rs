/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::convert::TryInto;

use ed25519_dalek::{Digest, SigningKey};

use crate::random::SecureRandom;

pub const C25519_PUBLIC_KEY_SIZE: usize = 32;
pub const C25519_SECRET_KEY_SIZE: usize = 32;
pub const C25519_SHARED_SECRET_SIZE: usize = 32;
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
pub const ED25519_SECRET_KEY_SIZE: usize = 32;
pub const ED25519_SIGNATURE_SIZE: usize = 64;

fn create_domain_restricted_digest(domain: &[u8], data: &[u8]) -> ed25519_dalek::Sha512 {
    debug_assert!(domain.len() <= u16::MAX as usize);
    let mut hasher = ed25519_dalek::Sha512::new();
    hasher.update(data);
    // We hash the domain last to mitigate some of the weaknesses of merkle-damgard.
    if domain.len() > 0 {
        hasher.update(domain);
        hasher.update(&(domain.len() as u16).to_be_bytes());
    }
    hasher
}

/// Curve25519 key pair for ECDH key agreement.
#[derive(Clone)]
pub struct X25519KeyPair(x25519_dalek::StaticSecret, x25519_dalek::PublicKey);

impl X25519KeyPair {
    pub fn generate() -> X25519KeyPair {
        let sk = x25519_dalek::StaticSecret::random_from_rng(SecureRandom);
        let pk = x25519_dalek::PublicKey::from(&sk);
        X25519KeyPair(sk, pk)
    }

    #[must_use]
    pub fn from_bytes(
        public_key: &[u8; C25519_PUBLIC_KEY_SIZE],
        secret_key: &[u8; C25519_SECRET_KEY_SIZE],
    ) -> Option<X25519KeyPair> {
        /* NOTE: we keep the original secret separately from x25519_dalek's StaticSecret
         * due to how "clamping" is done in the old C++ code vs x25519_dalek. Clamping
         * is explained here:
         *
         * https://www.jcraige.com/an-explainer-on-ed25519-clamping
         *
         * The old code does clamping at the time of use. In other words the code that
         * performs things like key agreement or signing clamps the secret before doing
         * the operation. The x25519_dalek code does clamping at generation or when
         * from() is used to get a key from a raw byte array.
         *
         * Unfortunately this introduces issues when interoperating with old code. The
         * old system generates secrets that are not clamped (since they're clamped at
         * use!) and assumes that these exact binary keys will be preserved in e.g.
         * identities. So to preserve this behavior we store the secret separately
         * so secret_bytes() will return it as-is.
         *
         * The new code will still clamp at generation resulting in secrets that are
         * pre-clamped, but the old code won't care about this. It's only a problem when
         * going the other way.
         *
         * This has no cryptographic implication since regardless of where, the clamping
         * is done. It's just an API thing.
         */
        let pk = x25519_dalek::PublicKey::from(*public_key);
        let sk = x25519_dalek::StaticSecret::from(*secret_key);
        Some(X25519KeyPair(sk, pk))
    }

    #[inline(always)]
    pub fn public_bytes(&self) -> [u8; C25519_PUBLIC_KEY_SIZE] {
        self.1.to_bytes()
    }

    #[inline(always)]
    pub fn secret_bytes(&self, output: &mut [u8; C25519_SECRET_KEY_SIZE]) {
        *output = self.0.to_bytes()
    }

    /// Execute ECDH agreement and return a raw (un-hashed) shared secret key.
    pub fn agree(&self, their_public: &[u8; C25519_PUBLIC_KEY_SIZE], output: &mut [u8; C25519_SHARED_SECRET_SIZE]) {
        let pk = x25519_dalek::PublicKey::from(*their_public);
        let sec = self.0.diffie_hellman(&pk);
        output.copy_from_slice(sec.as_bytes());
    }
}

/// Ed25519 key pair for EDDSA signatures.
#[derive(Clone)]
pub struct Ed25519KeyPair(SigningKey);

impl Ed25519KeyPair {
    #[must_use]
    pub fn generate() -> Ed25519KeyPair {
        let kp = SigningKey::generate(&mut SecureRandom);
        Ed25519KeyPair(kp)
    }

    pub fn from_bytes(
        public_bytes: &[u8; ED25519_PUBLIC_KEY_SIZE],
        secret_bytes: &[u8; ED25519_SECRET_KEY_SIZE],
    ) -> Option<Ed25519KeyPair> {
        let key = Ed25519KeyPair(SigningKey::try_from(secret_bytes).ok()?);

        if &key.public_bytes() != public_bytes {
            return None;
        }
        Some(key)
    }

    #[inline(always)]
    pub fn public_bytes(&self) -> [u8; ED25519_PUBLIC_KEY_SIZE] {
        self.0.verifying_key().to_bytes()
    }

    #[inline(always)]
    pub fn secret_bytes(&self, output: &mut [u8; ED25519_SECRET_KEY_SIZE]) {
        *output = self.0.to_bytes();
    }

    /// Sign a hash of the message (no domain parameter).
    pub fn sign(&self, msg: &[u8]) -> [u8; ED25519_SIGNATURE_SIZE] {
        let mut h = ed25519_dalek::Sha512::new();
        let _ = h.update(msg);
        self.0.sign_prehashed(h, None).unwrap().to_bytes()
    }

    /// Sign a hash of the message that includes a domain parameter.
    pub fn sign_domain_restricted(&self, domain: &[u8], msg: &[u8]) -> [u8; ED25519_SIGNATURE_SIZE] {
        self.0
            .sign_prehashed(create_domain_restricted_digest(domain, msg), None)
            .unwrap()
            .to_bytes()
    }

    /// Create a signature with the first 32 bytes of the SHA512 hash appended.
    /// This is for legacy ZeroTier V1 compatibility requirements. It's not used in newer code.
    pub fn sign_zt(&self, msg: &[u8]) -> [u8; 96] {
        let mut h = ed25519_dalek::Sha512::new();
        let _ = h.update(msg);
        let sig = self.0.sign_prehashed(h.clone(), None).unwrap();
        let s = sig.to_bytes();
        let mut s2 = [0_u8; 96];
        s2[0..64].copy_from_slice(&s);
        let h = h.finalize();
        s2[64..96].copy_from_slice(&h.as_slice()[0..32]);
        s2
    }
}

/// Verify a non-domain-restricted signature.
#[must_use]
pub fn ed25519_verify(public_key: &[u8; ED25519_PUBLIC_KEY_SIZE], signature: &[u8], msg: &[u8]) -> bool {
    if signature.len() >= 64 {
        ed25519_dalek::VerifyingKey::from_bytes(public_key.try_into().unwrap()).map_or(false, |pk| {
            let mut h = ed25519_dalek::Sha512::new();
            let _ = h.update(msg);
            let sig: [u8; 64] = signature[0..64].try_into().unwrap();
            pk.verify_prehashed(h, None, &ed25519_dalek::Signature::from(sig))
                .is_ok()
        })
    } else {
        false
    }
}

/// Verify a domain restricted signature.
#[must_use]
pub fn ed25519_verify_domain_restricted(
    public_key: &[u8; ED25519_PUBLIC_KEY_SIZE],
    signature: &[u8],
    domain: &[u8],
    msg: &[u8],
) -> bool {
    if signature.len() >= 64 {
        ed25519_dalek::VerifyingKey::from_bytes(public_key.try_into().unwrap()).map_or(false, |pk| {
            let sig: [u8; 64] = signature[0..64].try_into().unwrap();
            pk.verify_prehashed(
                create_domain_restricted_digest(domain, msg),
                None,
                &ed25519_dalek::Signature::from(sig),
            )
            .is_ok()
        })
    } else {
        false
    }
}
