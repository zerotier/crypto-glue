/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

// Version using OpenSSL's ECC
use std::os::raw::{c_int, c_ulong, c_void};
use std::sync::Mutex;
use std::{mem, ptr};

use crate::hash::{SHA384, SHA384_HASH_SIZE};
use crate::random::rand_core::{CryptoRng, RngCore};
use crate::secure_eq;

use once_cell::sync::Lazy;
use zssp::crypto_impl::openssl_sys as ffi;

pub const P384_PUBLIC_KEY_SIZE: usize = 49;
pub const P384_SECRET_KEY_SIZE: usize = 48;
pub const P384_ECDSA_SIGNATURE_SIZE: usize = 96;
pub const P384_ECDH_SHARED_SECRET_SIZE: usize = 48;

#[inline]
pub fn check_ptr<T>(r: *mut T) -> Result<*mut T, ()> {
    if r.is_null() {
        Err(())
    } else {
        Ok(r)
    }
}

#[inline]
pub fn check_gtz(r: c_int) -> Result<c_int, ()> {
    if r <= 0 {
        Err(())
    } else {
        Ok(r)
    }
}

#[inline]
pub fn check_gteqz(r: c_int) -> Result<c_int, ()> {
    if r < 0 {
        Err(())
    } else {
        Ok(r)
    }
}

extern "C" {
    fn ECDH_compute_key(
        out: *mut u8,
        outlen: c_ulong,
        pub_key: *const ffi::EC_POINT,
        ecdh: *mut ffi::EC_KEY,
        kdf: *const c_void,
    ) -> c_int;
}
/// A NIST P-384 ECDH/ECDSA public key.
pub struct P384PublicKey {
    /// OpenSSL does not guarantee threadsafety for this object (even though it could) so we have
    /// to wrap this in a mutex.
    key: Mutex<OSSLKey>,
    bytes: [u8; P384_PUBLIC_KEY_SIZE],
}

unsafe impl Send for P384PublicKey {}
unsafe impl Sync for P384PublicKey {}

fn create_domain_restricted_digest(domain: &[u8], data: &[&[u8]]) -> [u8; SHA384_HASH_SIZE] {
    debug_assert!(domain.len() <= u16::MAX as usize);
    let mut hasher = SHA384::new();
    for msg in data {
        hasher.update(msg);
    }
    // We hash the domain last to mitigate some of the weaknesses of merkle-damgard.
    if domain.len() > 0 {
        hasher.update(domain);
        hasher.update(&(domain.len() as u16).to_be_bytes());
    }
    hasher.finish()
}

impl P384PublicKey {
    /// Create a p384 public key from raw bytes.
    /// `buffer` must have length `P384_PUBLIC_KEY_SIZE`.
    pub fn from_bytes(buffer: &[u8]) -> Option<P384PublicKey> {
        if buffer.len() == P384_PUBLIC_KEY_SIZE {
            unsafe {
                // Write the buffer into OpenSSL.
                let key = OSSLKey::pub_from_slice(buffer).ok()?;
                // Get OpenSSL to double check if this final key makes sense.
                // It will be read-only after this point.
                if ffi::EC_KEY_check_key(key.0) == 1 {
                    let mut bytes = [0u8; P384_PUBLIC_KEY_SIZE];
                    bytes.clone_from_slice(buffer);
                    return Some(Self { key: Mutex::new(key), bytes });
                }
            }
        }
        None
    }

    /// Verify the ECDSA/SHA384 signature.
    ///
    /// Domain strings are prepended to a message with their length and then signed along with the
    /// entire message.
    /// This function will prepend nothing to the message and instead verify the message alone.
    pub fn verify_raw(&self, message: &[u8], signature: &[u8; P384_ECDSA_SIGNATURE_SIZE]) -> bool {
        self.verify_all(&[], &[message], signature)
    }
    /// Verify the ECDSA/SHA384 signature for a message with a specific domain.
    pub fn verify(&self, domain: &[u8], message: &[u8], signature: &[u8; P384_ECDSA_SIGNATURE_SIZE]) -> bool {
        self.verify_all(domain, &[message], signature)
    }
    /// Verify the ECDSA/SHA384 signature for a message with a specific domain.
    /// The signature is assumed to be for the message equal to all slices of `data`
    /// concatenated in order.
    pub fn verify_all(&self, domain: &[u8], data: &[&[u8]], signature: &[u8; P384_ECDSA_SIGNATURE_SIZE]) -> bool {
        const CAP: usize = P384_ECDSA_SIGNATURE_SIZE / 2;
        unsafe {
            // Write the raw bytes into OpenSSL.
            let r = OSSLBN::from_slice(&signature[..CAP]);
            let s = OSSLBN::from_slice(&signature[CAP..]);
            if let (Ok(r), Ok(s)) = (r, s) {
                // Create the OpenSSL object that actually supports verification.
                if let Ok(sig) = check_ptr(ffi::ECDSA_SIG_new()) {
                    cfg_if::cfg_if! {
                        if #[cfg(stinkysll)] {
                            let sig_deref = sig.as_mut().unwrap();
                            if !sig_deref.r.is_null() {
                                ffi::BN_free(sig_deref.r);
                            }
                            if !sig_deref.s.is_null() {
                                ffi::BN_free(sig_deref.s);
                            }
                            sig_deref.r = r.0;
                            sig_deref.s = s.0;
                        } else {
                            assert!(ffi::ECDSA_SIG_set0(sig, r.0, s.0) == 1);
                        }
                    }
                    // For some reason this one random function, `ECDSA_SIG_set0`, takes
                    // ownership of its parameters. I've double checked and it is the only one
                    // we call that does that. We `forget` the memory so we don't double free.
                    mem::forget(r);
                    mem::forget(s);
                    // Digest the message.
                    let digest = create_domain_restricted_digest(domain, data);

                    let key = self.key.lock().unwrap();
                    // Actually perform the verification.
                    let is_valid = ffi::ECDSA_do_verify(digest.as_ptr(), digest.len() as c_int, sig, key.0) == 1;
                    // Guarantee signature free.
                    ffi::ECDSA_SIG_free(sig);
                    return is_valid;
                }
            }
        }
        false
    }

    pub fn as_bytes(&self) -> &[u8; P384_PUBLIC_KEY_SIZE] {
        &self.bytes
    }
}
impl Clone for P384PublicKey {
    fn clone(&self) -> Self {
        Self {
            key: Mutex::new(self.key.lock().unwrap().clone_public().unwrap()),
            bytes: self.bytes,
        }
    }
}
impl PartialEq for P384PublicKey {
    fn eq(&self, other: &Self) -> bool {
        secure_eq(&self.bytes, &other.bytes)
    }
}

/// A NIST P-384 ECDH/ECDSA public/private key pair.
pub struct P384KeyPair {
    /// OpenSSL does not guarantee threadsafety for this object (even though it could) so we have
    /// to wrap this in a mutex.
    pair: Mutex<OSSLKey>,
    pub_bytes: [u8; P384_PUBLIC_KEY_SIZE],
}

unsafe impl Send for P384KeyPair {}
unsafe impl Sync for P384KeyPair {}

impl P384KeyPair {
    /// Randomly generate a new p384 keypair.
    pub fn generate() -> P384KeyPair {
        unsafe {
            let pair = OSSLKey::new().unwrap();
            // Ask OpenSSL to securely generate the keypair.
            check_gtz(ffi::EC_KEY_generate_key(pair.0)).unwrap();
            // Read out the raw public key into a buffer.
            let public_key = ffi::EC_KEY_get0_public_key(pair.0);
            let mut buffer = [0_u8; P384_PUBLIC_KEY_SIZE];
            let bnc = OSSLBNC::new().unwrap();
            assert!(
                ffi::EC_POINT_point2oct(
                    GROUP_P384.0,
                    public_key,
                    ffi::point_conversion_form_t::POINT_CONVERSION_COMPRESSED,
                    buffer.as_mut_ptr(),
                    P384_PUBLIC_KEY_SIZE,
                    bnc.0,
                ) > 0
            );
            Self { pair: Mutex::new(pair), pub_bytes: buffer }
        }
    }

    /// Create a p384 keypair from raw bytes.
    /// `public_bytes` should have length `P384_PUBLIC_KEY_SIZE` and `secret_bytes` should have length
    /// `P384_SECRET_KEY_SIZE`.
    pub fn from_bytes(
        public_bytes: &[u8; P384_PUBLIC_KEY_SIZE],
        secret_bytes: &[u8; P384_SECRET_KEY_SIZE],
    ) -> Option<P384KeyPair> {
        unsafe {
            // Write the raw bytes into OpenSSL.
            let pair = OSSLKey::pub_from_slice(public_bytes).ok()?;
            let private = OSSLBN::from_slice(secret_bytes).ok()?;
            // Tell OpenSSL to assign the private key to the public key.
            // This makes the public key into a proper keypair.
            if check_gtz(ffi::EC_KEY_set_private_key(pair.0, private.0)).is_ok() {
                // Get OpenSSL to double check if this final key makes sense.
                // It will be read-only after this point.
                if ffi::EC_KEY_check_key(pair.0) == 1 {
                    let mut pub_bytes = [0u8; P384_PUBLIC_KEY_SIZE];
                    pub_bytes.clone_from_slice(public_bytes);
                    return Some(Self { pair: Mutex::new(pair), pub_bytes });
                }
            }
        }
        None
    }
    /// Create a new `P384PublicKey` object that only contains the public key from
    /// this keypair. This object can be safely sent to a different thread.
    pub fn to_public_key(&self) -> P384PublicKey {
        let key = self.pair.lock().unwrap().clone_public().unwrap();
        P384PublicKey { key: Mutex::new(key), bytes: self.pub_bytes }
    }
    /// Get the raw bytes that uniquely define the public key.
    pub fn public_key_bytes(&self) -> &[u8; P384_PUBLIC_KEY_SIZE] {
        &self.pub_bytes
    }

    /// Clone the raw bytes that uniquely define the secret key.
    /// They are wrapped in a container which will erase them on drop.
    ///
    /// **Only write these to 100% trusted storage mediums. Avoid calling this function in general.**
    pub fn secret_key_bytes(&self, output: &mut [u8; P384_SECRET_KEY_SIZE]) {
        unsafe {
            let keypair = self.pair.lock().unwrap();
            // Get a temporary handle to the private key.
            let ptr = ffi::EC_KEY_get0_private_key(keypair.0);
            // Read the key's raw bytes out of OpenSSL.
            let size = check_gteqz(ffi::BN_bn2bin(ptr, output.as_mut_ptr())).unwrap() as usize;
            drop(keypair);

            // Double check big-endian-ness.
            output.copy_within(..size, P384_SECRET_KEY_SIZE - size);
        }
    }

    /// Sign a message with ECDSA/SHA384 without any domain restriction.
    ///
    /// Domain strings are prepended to a message with their length and then signed along with the
    /// entire message.
    /// This function will prepend nothing to the message and instead sign the message alone.
    /// It is not recommended to use this function unless this specific key was domain restricted
    /// upon generation.
    pub fn sign_raw(&self, message: &[u8]) -> [u8; P384_ECDSA_SIGNATURE_SIZE] {
        self.sign_all(&[], &[message])
    }
    /// Sign a message with ECDSA/SHA384.
    ///
    /// The signature will only be valid when verified with the same "domain".
    /// Restricting signatures to domains reduces the risk of a valid signature being used for a
    /// purpose the signer did not intend.
    ///
    /// A good domain string statically specifies what a signature is "for", and is strictly unique
    /// for each different thing a signature is "used for".
    pub fn sign(&self, domain: &[u8], message: &[u8]) -> [u8; P384_ECDSA_SIGNATURE_SIZE] {
        self.sign_all(domain, &[message])
    }
    /// Sign a message with ECDSA/SHA384.
    /// The produced signature will be for the message equal to all slices of `data`
    /// concatenated in order.
    ///
    /// The signature will only be valid when verified with the same "domain".
    /// Restricting signatures to domains reduces the risk of a valid signature being used for a
    /// purpose the signer did not intend.
    #[allow(unused_assignments)]
    pub fn sign_all(&self, domain: &[u8], data: &[&[u8]]) -> [u8; P384_ECDSA_SIGNATURE_SIZE] {
        let digest = create_domain_restricted_digest(domain, data);
        unsafe {
            let keypair = self.pair.lock().unwrap();
            // Actually create the signature with ECDSA.
            let sig = check_ptr(ffi::ECDSA_do_sign(digest.as_ptr(), digest.len() as c_int, keypair.0));
            drop(keypair);
            let sig = sig.unwrap();

            // Get handles to the OpenSSL objects that actually support reading out into bytes.
            let mut r = ptr::null();
            let mut s = ptr::null();
            cfg_if::cfg_if! {
                if #[cfg(stinkysll)] {
                    let sig_deref = sig.as_ref().unwrap();
                    r = sig_deref.r;
                    s = sig_deref.s;
                } else {
                    ffi::ECDSA_SIG_get0(sig, &mut r, &mut s);
                }
            }

            if r.is_null() || s.is_null() {
                ffi::ECDSA_SIG_free(sig);
                assert!(false);
            }
            // Determine the size of the buffers to guarantee sanity and big-endian-ness.
            let r_len = ((ffi::BN_num_bits(r) + 7) / 8) as usize;
            let s_len = ((ffi::BN_num_bits(s) + 7) / 8) as usize;
            const CAP: usize = P384_ECDSA_SIGNATURE_SIZE / 2;
            if !(r_len > 0 && s_len > 0 && r_len <= CAP && s_len <= CAP) {
                ffi::ECDSA_SIG_free(sig);
                assert!(false);
            }

            let mut b = [0_u8; P384_ECDSA_SIGNATURE_SIZE];
            // Read the signature's raw bytes out of OpenSSL.
            ffi::BN_bn2bin(r, b[(CAP - r_len)..CAP].as_mut_ptr());
            ffi::BN_bn2bin(
                s,
                b[(P384_ECDSA_SIGNATURE_SIZE - s_len)..P384_ECDSA_SIGNATURE_SIZE].as_mut_ptr(),
            );
            ffi::ECDSA_SIG_free(sig);
            b
        }
    }

    /// Perform ECDH key agreement, returning the raw (un-hashed!) ECDH secret.
    ///
    /// This secret should not be used directly. It should be hashed and perhaps used in a KDF.
    pub fn agree(&self, other_public: &P384PublicKey, output: &mut [u8; P384_ECDH_SHARED_SECRET_SIZE]) {
        let keypair = self.pair.lock().unwrap();
        let other_key = other_public.key.lock().unwrap();
        unsafe {
            // Ask OpenSSL to perform DH between the keypair and the other key's public key object.
            assert_eq!(
                ECDH_compute_key(
                    output.as_mut_ptr(),
                    P384_ECDH_SHARED_SECRET_SIZE as c_ulong,
                    ffi::EC_KEY_get0_public_key(other_key.0),
                    keypair.0,
                    ptr::null(),
                ),
                P384_ECDH_SHARED_SECRET_SIZE as c_int
            )
        }
    }
}

/// OpenSSL wrapper for a BN_CTX handle that guarantees free will be called.
struct OSSLBNC(*mut ffi::BN_CTX);
impl OSSLBNC {
    unsafe fn new() -> Result<Self, ()> {
        check_ptr(ffi::BN_CTX_new()).map(Self)
    }
}
impl Drop for OSSLBNC {
    fn drop(&mut self) {
        unsafe {
            ffi::BN_CTX_free(self.0);
        }
    }
}
/// OpenSSL wrapper for a BIGNUM handle that guarantees free will be called.
struct OSSLBN(*mut ffi::BIGNUM);
impl OSSLBN {
    /// We would use OpenSSL's newer API for p384 if it actually supported raw byte encodings of keys.
    /// Until then we are stuck with the old API.
    unsafe fn from_slice(n: &[u8]) -> Result<Self, ()> {
        check_ptr(ffi::BN_bin2bn(n.as_ptr(), n.len() as c_int, ptr::null_mut())).map(Self)
    }
}
impl Drop for OSSLBN {
    fn drop(&mut self) {
        unsafe {
            ffi::BN_free(self.0);
        }
    }
}
/// OpenSSL wrapper for a EC_KEY handle that guarantees free will be called.
struct OSSLKey(*mut ffi::EC_KEY);
impl OSSLKey {
    /// Create an empty key, guaranteeing to the caller it has the correct group and will be freed.
    unsafe fn new() -> Result<Self, ()> {
        let key = check_ptr(ffi::EC_KEY_new())?;
        check_gtz(ffi::EC_KEY_set_group(key, GROUP_P384.0))?;
        Ok(Self(key))
    }
    /// Create a key, guaranteeing to the caller it has the correct group, has a public key and will be freed.
    ///
    /// We would use OpenSSL's newer API for p384 if it actually supported raw byte encodings of keys.
    /// Until then we are stuck with the old API.
    unsafe fn pub_from_slice(buffer: &[u8]) -> Result<OSSLKey, ()> {
        /// The public key is an ec_point, we need to be sure we free its memory
        struct Point(*mut ffi::EC_POINT);
        impl Point {
            unsafe fn new() -> Result<Self, ()> {
                check_ptr(ffi::EC_POINT_new(GROUP_P384.0)).map(Self)
            }
        }
        impl Drop for Point {
            fn drop(&mut self) {
                unsafe {
                    ffi::EC_POINT_free(self.0);
                }
            }
        }
        let bnc = OSSLBNC::new()?;
        let point = Point::new()?;
        // Ask OpenSSL to read the raw bytes into the OpenSSL object.
        check_gtz(ffi::EC_POINT_oct2point(
            GROUP_P384.0,
            point.0,
            buffer.as_ptr(),
            buffer.len(),
            bnc.0,
        ))?;
        // Check if the object is valid.
        if check_gteqz(ffi::EC_POINT_is_on_curve(GROUP_P384.0, point.0, bnc.0))? == 1 {
            // Create an OpenSSL key and guarantee to the caller that the key was initialized with a
            // public key.
            let ec_key = OSSLKey::new()?;
            check_gtz(ffi::EC_KEY_set_public_key(ec_key.0, point.0))?;
            Ok(ec_key)
        } else {
            Err(())
        }
    }
    /// Create a `Send`-able clone of the public key. We don't reference count for this reason.
    fn clone_public(&self) -> Result<Self, ()> {
        unsafe {
            let point = ffi::EC_KEY_get0_public_key(self.0);
            // Create an OpenSSL key and guarantee to the caller that the key was initialized with a
            // public key.
            let key = OSSLKey::new()?;
            check_gtz(ffi::EC_KEY_set_public_key(key.0, point))?;
            Ok(key)
        }
    }
}
impl Drop for OSSLKey {
    fn drop(&mut self) {
        unsafe {
            ffi::EC_KEY_free(self.0);
        }
    }
}
/// OpenSSL wrapper for a EC_GROUP that is used to tell rust that an OpenSSL EC_GROUP is threadsafe.
/// We only ever instantiate one of these with lazy_static. It is never freed.
struct OSSLGroup(*mut ffi::EC_GROUP);
unsafe impl Send for OSSLGroup {}
unsafe impl Sync for OSSLGroup {}
static GROUP_P384: Lazy<OSSLGroup> =
    Lazy::new(|| unsafe { OSSLGroup(check_ptr(ffi::EC_GROUP_new_by_curve_name(ffi::NID_secp384r1)).unwrap()) });

/* Start of ZSSP Impl */

impl zssp::crypto::P384PublicKey for P384PublicKey {
    fn from_bytes(raw_key: &[u8; P384_PUBLIC_KEY_SIZE]) -> Option<Self> {
        Self::from_bytes(raw_key)
    }

    fn to_bytes(&self) -> [u8; P384_PUBLIC_KEY_SIZE] {
        self.bytes
    }
}

impl<Rng: RngCore + CryptoRng> zssp::crypto::P384KeyPair<Rng> for P384KeyPair {
    type PublicKey = P384PublicKey;

    fn generate(_: &mut Rng) -> Self {
        Self::generate()
    }

    fn public_key_bytes(&self) -> [u8; P384_PUBLIC_KEY_SIZE] {
        *self.public_key_bytes()
    }

    fn agree(&self, other_public: &P384PublicKey, output: &mut [u8; P384_ECDH_SHARED_SECRET_SIZE]) {
        self.agree(other_public, output)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        p384::{
            P384KeyPair, P384_ECDH_SHARED_SECRET_SIZE, P384_ECDSA_SIGNATURE_SIZE, P384_PUBLIC_KEY_SIZE,
            P384_SECRET_KEY_SIZE,
        },
        secure_eq,
    };

    #[test]
    fn generate_sign_verify_agree() {
        let kp = P384KeyPair::generate();
        let kp2 = P384KeyPair::generate();
        let kp_pub = kp.to_public_key();
        let kp2_pub = kp2.to_public_key();

        let sig = kp.sign_raw(&[0_u8; 16]);
        if !kp_pub.verify_raw(&[0_u8; 16], &sig) {
            panic!("ECDSA verify failed");
        }
        if kp_pub.verify_raw(&[1_u8; 16], &sig) {
            panic!("ECDSA verify succeeded for incorrect message");
        }

        let mut sec0 = [0u8; P384_ECDH_SHARED_SECRET_SIZE];
        let mut sec1 = [0u8; P384_ECDH_SHARED_SECRET_SIZE];
        kp.agree(&kp2_pub, &mut sec0);
        kp2.agree(&kp_pub, &mut sec1);
        if !secure_eq(&sec0, &sec1) {
            panic!("ECDH secrets do not match");
        }

        let pkb = kp.public_key_bytes();
        let mut skb = [0u8; P384_SECRET_KEY_SIZE];
        kp.secret_key_bytes(&mut skb);
        let kp3 = P384KeyPair::from_bytes(pkb, &skb).unwrap();

        let mut skb3 = [0u8; P384_SECRET_KEY_SIZE];
        let pkb3 = kp3.public_key_bytes();
        kp.secret_key_bytes(&mut skb3);

        assert_eq!(pkb, pkb3);
        assert_eq!(skb, skb3);

        let sig = kp3.sign_raw(&[3_u8; 16]);
        if !kp_pub.verify_raw(&[3_u8; 16], &sig) {
            panic!("ECDSA verify failed (from key reconstructed from bytes)");
        }
    }

    #[test]
    fn test_bad_key() {
        let kp_fake = P384KeyPair::generate();
        let kp = P384KeyPair::generate();
        let kp2 = P384KeyPair::generate();
        let kp_pub = kp.to_public_key();
        let kp2_pub = kp2.to_public_key();

        let sig = kp_fake.sign_raw(&[0_u8; 16]);
        if kp_pub.verify_raw(&[0_u8; 16], &sig) {
            panic!("ECDSA verify succeeded");
        }
        if kp_pub.verify_raw(&[1_u8; 16], &sig) {
            panic!("ECDSA verify succeeded for incorrect message");
        }

        let mut sec0 = [0u8; P384_ECDH_SHARED_SECRET_SIZE];
        let mut sec1 = [0u8; P384_ECDH_SHARED_SECRET_SIZE];
        kp_fake.agree(&kp2_pub, &mut sec0);
        kp2.agree(&kp_pub, &mut sec1);
        if secure_eq(&sec0, &sec1) {
            panic!("Bad ECDH secrets match");
        }
    }
    #[test]
    fn test_zero_key() {
        assert!(P384KeyPair::from_bytes(&[0u8; P384_PUBLIC_KEY_SIZE], &[0u8; P384_SECRET_KEY_SIZE]).is_none());
        let kp = P384KeyPair::generate();
        let kp_pub = kp.to_public_key();

        let mut sigs = [
            [0u8; P384_ECDSA_SIGNATURE_SIZE],
            [0u8; P384_ECDSA_SIGNATURE_SIZE],
            [0u8; P384_ECDSA_SIGNATURE_SIZE],
            [1u8; P384_ECDSA_SIGNATURE_SIZE],
        ];
        sigs[1][0] = 1;
        sigs[2][95] = 1;
        for sig in &sigs {
            if kp_pub.verify_raw(&[0_u8; 16], sig) {
                panic!("ECDSA verify succeeded on fake sig");
            }
        }
    }
}
