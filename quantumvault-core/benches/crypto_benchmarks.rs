//! Cryptographic operation benchmarks for QuantumVault.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use quantumvault_core::{Algorithm, Config, QuantumVault, SecurityLevel};

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");

    // Each algorithm needs matching security level
    for (level, algo, name) in [
        (SecurityLevel::Level1, Algorithm::MlKem512, "ML-KEM-512"),
        (SecurityLevel::Level3, Algorithm::MlKem768, "ML-KEM-768"),
        (SecurityLevel::Level5, Algorithm::MlKem1024, "ML-KEM-1024"),
    ] {
        let qv = QuantumVault::new(level).unwrap();

        group.bench_function(name, |b| {
            b.iter(|| {
                let _ = black_box(qv.keygen(algo).unwrap());
            });
        });
    }

    group.finish();
}

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt");

    let qv = QuantumVault::new(SecurityLevel::Level3).unwrap();
    let keypair = qv.keygen(Algorithm::MlKem768).unwrap();

    for size in [64, 256, 1024, 4096, 16384] {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let _ = black_box(qv.encrypt(data, &keypair.public_key).unwrap());
            });
        });
    }

    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt");

    let qv = QuantumVault::new(SecurityLevel::Level3).unwrap();
    let keypair = qv.keygen(Algorithm::MlKem768).unwrap();

    for size in [64, 256, 1024, 4096, 16384] {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let encrypted = qv.encrypt(&data, &keypair.public_key).unwrap();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &encrypted,
            |b, encrypted| {
                b.iter(|| {
                    let _ = black_box(qv.decrypt(encrypted, &keypair.secret_key).unwrap());
                });
            },
        );
    }

    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign");

    // Each algorithm needs matching security level
    for (level, algo, name) in [
        (SecurityLevel::Level1, Algorithm::MlDsa44, "ML-DSA-44"),
        (SecurityLevel::Level3, Algorithm::MlDsa65, "ML-DSA-65"),
        (SecurityLevel::Level5, Algorithm::MlDsa87, "ML-DSA-87"),
    ] {
        let config = Config::builder().security_level(level).build().unwrap();

        let keypair =
            quantumvault_core::api::keygen::generate_signature_keypair(algo, &config).unwrap();
        let message = b"Benchmark message for signing operations";

        group.bench_function(name, |b| {
            b.iter(|| {
                let _ = black_box(
                    quantumvault_core::api::sign::sign_message(
                        message,
                        &keypair.signing_key,
                        &config,
                    )
                    .unwrap(),
                );
            });
        });
    }

    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");

    // Each algorithm needs matching security level
    for (level, algo, name) in [
        (SecurityLevel::Level1, Algorithm::MlDsa44, "ML-DSA-44"),
        (SecurityLevel::Level3, Algorithm::MlDsa65, "ML-DSA-65"),
        (SecurityLevel::Level5, Algorithm::MlDsa87, "ML-DSA-87"),
    ] {
        let config = Config::builder().security_level(level).build().unwrap();

        let keypair =
            quantumvault_core::api::keygen::generate_signature_keypair(algo, &config).unwrap();
        let message = b"Benchmark message for verification operations";
        let signature =
            quantumvault_core::api::sign::sign_message(message, &keypair.signing_key, &config)
                .unwrap();

        group.bench_function(name, |b| {
            b.iter(|| {
                let _ = black_box(
                    quantumvault_core::api::verify::verify_signature(
                        message,
                        &signature,
                        &keypair.verifying_key,
                        &config,
                    )
                    .unwrap(),
                );
            });
        });
    }

    group.finish();
}

fn bench_security_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("security_levels");

    for (level, algo, name) in [
        (
            SecurityLevel::Level1,
            Algorithm::MlKem512,
            "Level1-ML-KEM-512",
        ),
        (
            SecurityLevel::Level3,
            Algorithm::MlKem768,
            "Level3-ML-KEM-768",
        ),
        (
            SecurityLevel::Level5,
            Algorithm::MlKem1024,
            "Level5-ML-KEM-1024",
        ),
    ] {
        let qv = QuantumVault::new(level).unwrap();
        let keypair = qv.keygen(algo).unwrap();
        let data = b"Security level comparison benchmark data";

        group.bench_function(name, |b| {
            b.iter(|| {
                let encrypted = qv.encrypt(data, &keypair.public_key).unwrap();
                let _ = black_box(qv.decrypt(&encrypted, &keypair.secret_key).unwrap());
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_keygen,
    bench_encrypt,
    bench_decrypt,
    bench_sign,
    bench_verify,
    bench_security_levels,
);

criterion_main!(benches);
