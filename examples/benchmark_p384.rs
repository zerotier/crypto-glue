use std::time::Duration;

use zerotier_crypto_glue::p384::{P384KeyPair, P384PublicKey, P384_ECDH_SHARED_SECRET_SIZE};

fn to_rate(iters: u32, start_time: Duration, final_time: Duration) -> f64 {
    let d = (final_time.as_nanos() - start_time.as_nanos()) as f64 / 1000000000.0;
    iters as f64 / d
}

fn main() {
    let startup_time = std::time::Instant::now();
    let mut args = std::env::args();
    args.next();

    let iters = match args.next() {
        Some(s) => u32::from_str_radix(&s, 10).expect("first argument must be a number"),
        _ => 5000u32,
    };
    println!("running each benchmark with {} iterations...", iters);

    /* Generate */

    let mut _kp0 = P384KeyPair::generate();
    let kp1 = P384KeyPair::generate();
    let kp2 = P384KeyPair::generate();
    let start_time = startup_time.elapsed();
    for _ in 0..iters {
        _kp0 = P384KeyPair::generate();
    }
    let final_time = startup_time.elapsed();
    println!(
        "p384 generate and drop:     {} keys/sec",
        to_rate(iters, start_time, final_time)
    );

    /* From bytes */

    let pk = kp2.public_key_bytes();
    let mut pubkey = P384PublicKey::from_bytes(pk).unwrap();
    let start_time = startup_time.elapsed();
    for _ in 0..iters {
        pubkey = P384PublicKey::from_bytes(pk).unwrap();
    }
    let final_time = startup_time.elapsed();
    println!(
        "p384 public key from bytes: {} keys/sec",
        to_rate(iters, start_time, final_time)
    );

    /* Agree */

    let mut output = [0u8; P384_ECDH_SHARED_SECRET_SIZE];
    let start_time = startup_time.elapsed();
    for _ in 0..iters {
        kp1.agree(&pubkey, &mut output);
    }
    let final_time = startup_time.elapsed();
    println!(
        "p384 key agreement:         {} ecdh/sec",
        to_rate(iters, start_time, final_time)
    );

    /* Sign */

    let input = [1u8; P384_ECDH_SHARED_SECRET_SIZE];
    let mut output = kp2.sign_raw(&input);
    let start_time = startup_time.elapsed();
    for _ in 0..iters {
        output = kp2.sign_raw(&input);
    }
    let final_time = startup_time.elapsed();
    println!(
        "p384 signature:             {} sig/sec",
        to_rate(iters, start_time, final_time)
    );

    /* Sign Stream */

    let domain = [2u8; P384_ECDH_SHARED_SECRET_SIZE];
    let input = [1u8; P384_ECDH_SHARED_SECRET_SIZE];
    let start_time = startup_time.elapsed();
    for _ in 0..iters {
        output = kp2.sign(&domain, &input);
    }
    let final_time = startup_time.elapsed();
    println!(
        "p384 sign with domain:      {} sig/sec",
        to_rate(iters, start_time, final_time)
    );

    /* Verify */

    let start_time = startup_time.elapsed();
    for _ in 0..iters {
        assert!(pubkey.verify(&domain, &input, &output));
    }
    let final_time = startup_time.elapsed();
    println!(
        "p384 verify with domain:    {} sig/sec",
        to_rate(iters, start_time, final_time)
    );
}
