
# Benchmarks

All benchmarks are run with [Criterion.rs](https://github.com/bheisler/criterion.rs) statistical benchmarking on standard hardware. Each measurement is the median of thousands of iterations with warm-up and outlier detection.

## Summary

| Operation | Time | Notes |
|:---|---:|:---|
| Ed25519 key generation | **8.80 us** | Fresh key pair from OS CSPRNG |
| Ed25519 sign | **9.17 us** | Sign 44-byte message |
| Ed25519 verify | **19.34 us** | Verify signature on same message |
| HKDF-SHA256 derivation | **972 ns** | Derive 32-byte child key from root |
| Identity creation | **8.78 us** | Generate key pair + compute ID |
| Receipt sign | **11.55 us** | Hash + ID generation + Ed25519 sign |
| Receipt verify | **21.77 us** | Decode key + verify signature |
| Trust grant sign | **12.41 us** | Hash + ID generation + Ed25519 sign |
| Trust grant verify | **21.84 us** | Decode key + verify signature |
| Trust chain verify (depth 2) | **43.51 us** | 2 signature verifications + chain walk |
| Receipt chain (10 receipts) | **123.77 us** | Create identity + sign 10 chained receipts |

## Analysis

### Signing vs. Verification

Ed25519 verification (~19 us) is approximately 2x slower than signing (~9 us). This is expected: verification requires a decompression step on the public key point that signing avoids. All AgenticIdentity verification operations are dominated by this Ed25519 verify cost.

### Key Derivation

HKDF-SHA256 derivation runs at **972 nanoseconds** -- sub-microsecond. Deriving session keys, capability keys, or device keys adds negligible overhead compared to the signing operations that follow.

### Receipt Operations

Receipt signing (11.55 us) adds roughly 2.4 us of overhead beyond raw Ed25519 signing (9.17 us) for SHA-256 hashing, base64 encoding, ID computation, and struct assembly. Receipt verification (21.77 us) adds roughly 2.4 us beyond raw Ed25519 verification for base64 decoding and hash extraction.

### Trust Operations

Trust grant operations have similar overhead profiles to receipts. Grant signing (12.41 us) and verification (21.84 us) include capability serialization and constraint checking in addition to the cryptographic core.

### Chain Verification

Trust chain verification scales linearly with depth. A depth-2 chain (43.51 us) is approximately 2x the cost of a single grant verification (21.84 us), confirming that there is no superlinear overhead from chain walking.

### Receipt Chain Creation

Creating a chain of 10 receipts (123.77 us) includes one identity creation (~8.78 us) and 10 receipt signings (~11.55 us each). The total closely matches the sum of individual operations: 8.78 + (10 x 11.55) = 124.28 us, confirming no hidden per-chain overhead.

## Throughput Estimates

For planning capacity:

| Operation | Estimated throughput |
|:---|---:|
| Identity creation | ~114,000 / sec |
| Receipt signing | ~86,600 / sec |
| Receipt verification | ~45,900 / sec |
| Trust grant signing | ~80,600 / sec |
| Trust grant verification | ~45,800 / sec |
| Trust chain verify (depth 2) | ~22,900 / sec |

These are single-threaded estimates. All operations are independent and scale linearly with CPU cores.

## Reproduction

Run the benchmarks yourself:

```bash
cargo bench -p agentic-identity
```

Results are written to `target/criterion/` with HTML reports including statistical distributions, iteration counts, and regression detection.

## What is NOT Benchmarked Here

- **Argon2id passphrase derivation** is intentionally slow (~200-500 ms) and is not included in the table above. It runs only during `.aid` file save/load operations.
- **File I/O** (disk read/write) is excluded because it depends on storage hardware.
- **Network latency** for revocation channel checks is excluded because it depends on infrastructure.
