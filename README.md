# pqc-constrained-bench

Reproducible measurements of NIST post-quantum cryptography (ML-KEM, FIPS 203; ML-DSA, FIPS 204) against classical algorithms (X25519, ECDSA P-256, Ed25519), as a first step toward an open benchmark and integration guide for constrained wireless and IoT devices.

**Author:** Iqra Batool, Ph.D., University of New Brunswick

## Contents
| File | What it is |
|---|---|
| `pqc_bench.py` | Benchmark script: times key generation, encapsulation/decapsulation and signing/verification at every standardized parameter set, and records key, ciphertext and signature sizes |
| `make_report.py` | Builds the technical report PDF from the benchmark output |
| `colab.csv` | Raw results, Google Colab cloud VM, 1,000 runs per operation (October 11, 2026, UTC; October 10 local time) |
| `colab_device.json` | Hardware and software description of the platform that produced `colab.csv` |
| `Batool_PQC_Report.pdf` | Technical report |

## Key finding
On a general-purpose platform, post-quantum operations take tens to hundreds of microseconds, comparable to classical algorithms. Message size is the larger burden: one ML-KEM-768 exchange sends 2,272 bytes versus 64 for X25519, and an ML-DSA-65 public key plus signature is 5,261 bytes versus 96 for Ed25519. These sizes are identical on every platform, so they apply directly to low-power wireless links.

## Reproduce
See the setup notes at the top of `pqc_bench.py`, then:
```
python3 pqc_bench.py --runs 1000 --out mydevice
python3 make_report.py --runs mydevice --names "My device" --baseline-only --out report.pdf
```

## Next steps
Timing and energy measurements on constrained hardware (single-board computers and microcontrollers), full hybrid handshakes, and signed firmware updates over low-power links.

## Acknowledgment
The benchmark and report-generation scripts were developed with the assistance of an AI tool (Claude, Anthropic). The author ran all measurements, reviewed the code and results, and is responsible for the content.
