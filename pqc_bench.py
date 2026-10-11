#!/usr/bin/env python3
"""
PQC cost benchmark for constrained devices (Raspberry Pi, gateway, laptop baseline).

Measures key generation, encapsulation/decapsulation (ML-KEM) and sign/verify (ML-DSA)
at every standardized parameter set, plus classical baselines (X25519, ECDSA P-256, Ed25519),
and records object sizes. Results go to a CSV plus a JSON file describing the device, so
every number in your report is reproducible.

Setup (Raspberry Pi OS / Ubuntu), about 10 minutes on a Pi 4:
    sudo apt install git cmake ninja-build gcc libssl-dev python3-pip python3-venv
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
    cmake -S liboqs -B liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
          -DCMAKE_INSTALL_PREFIX=$HOME/_oqs
    ninja -C liboqs/build install
    python3 -m venv pqc && . pqc/bin/activate
    pip install liboqs-python cryptography psutil
    export OQS_INSTALL_PATH=$HOME/_oqs LD_LIBRARY_PATH=$HOME/_oqs/lib

Run:
    python3 pqc_bench.py --runs 1000 --out results_rpi4
    python3 pqc_bench.py --runs 200  --out results_rpi_zero   # slower boards

Energy (optional): plug the device into a USB power meter, note the average watts during
each phase, and multiply by the per-operation time from the CSV.
"""
import argparse, csv, json, os, platform, statistics, sys, time

try:
    import oqs
except ImportError:
    sys.exit("liboqs-python is not installed: pip install liboqs-python")

from cryptography.hazmat.primitives.asymmetric import x25519, ec, ed25519
from cryptography.hazmat.primitives import hashes, serialization

KEMS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
SIGS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
MSG = os.urandom(256)  # representative signed control message / firmware-manifest digest size


def timeit(fn, runs, warmup=20):
    for _ in range(warmup):
        fn()
    out = []
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        fn()
        out.append((time.perf_counter_ns() - t0) / 1000.0)  # microseconds
    out.sort()
    return {
        "median_us": statistics.median(out),
        "mean_us": statistics.fmean(out),
        "stdev_us": statistics.pstdev(out),
        "p95_us": out[int(0.95 * (len(out) - 1))],
        "min_us": out[0],
        "runs": runs,
    }


def bench_kem(name, runs):
    rows = []
    with oqs.KeyEncapsulation(name) as k:
        pk = k.generate_keypair()
        rows.append(("keygen", timeit(lambda: oqs.KeyEncapsulation(name).generate_keypair(), runs)))
        ct, ss = k.encap_secret(pk)
        rows.append(("encaps", timeit(lambda: k.encap_secret(pk), runs)))
        rows.append(("decaps", timeit(lambda: k.decap_secret(ct), runs)))
        assert k.decap_secret(ct) == ss, "decapsulation mismatch"
        sizes = {"public_key_B": len(pk), "ciphertext_B": len(ct), "shared_secret_B": len(ss),
                 "secret_key_B": k.details.get("length_secret_key")}
    return [(name, "KEM", op, st, sizes) for op, st in rows]


def bench_sig(name, runs):
    rows = []
    with oqs.Signature(name) as s:
        pk = s.generate_keypair()
        rows.append(("keygen", timeit(lambda: oqs.Signature(name).generate_keypair(), runs)))
        sig = s.sign(MSG)
        rows.append(("sign", timeit(lambda: s.sign(MSG), runs)))
        with oqs.Signature(name) as v:
            rows.append(("verify", timeit(lambda: v.verify(MSG, sig, pk), runs)))
            assert v.verify(MSG, sig, pk), "verification failed"
        sizes = {"public_key_B": len(pk), "signature_B": len(sig),
                 "secret_key_B": s.details.get("length_secret_key")}
    return [(name, "SIG", op, st, sizes) for op, st in rows]


def bench_classical(runs):
    res = []
    raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
    # X25519 key agreement (classical counterpart of ML-KEM)
    a, b = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    bpub = b.public_key()
    sz = {"public_key_B": len(bpub.public_bytes(*raw)), "shared_secret_B": 32}
    res.append(("X25519", "KEX", "keygen", timeit(x25519.X25519PrivateKey.generate, runs), sz))
    res.append(("X25519", "KEX", "exchange", timeit(lambda: a.exchange(bpub), runs), sz))
    # ECDSA P-256 (classical counterpart of ML-DSA)
    k = ec.generate_private_key(ec.SECP256R1()); pub = k.public_key()
    sig = k.sign(MSG, ec.ECDSA(hashes.SHA256()))
    sz = {"public_key_B": len(pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)),
          "signature_B_DER": len(sig)}
    res.append(("ECDSA-P256", "SIG", "keygen", timeit(lambda: ec.generate_private_key(ec.SECP256R1()), runs), sz))
    res.append(("ECDSA-P256", "SIG", "sign", timeit(lambda: k.sign(MSG, ec.ECDSA(hashes.SHA256())), runs), sz))
    res.append(("ECDSA-P256", "SIG", "verify", timeit(lambda: pub.verify(sig, MSG, ec.ECDSA(hashes.SHA256())), runs), sz))
    # Ed25519
    e = ed25519.Ed25519PrivateKey.generate(); epub = e.public_key(); esig = e.sign(MSG)
    sz = {"public_key_B": len(epub.public_bytes(*raw)), "signature_B": len(esig)}
    res.append(("Ed25519", "SIG", "sign", timeit(lambda: e.sign(MSG), runs), sz))
    res.append(("Ed25519", "SIG", "verify", timeit(lambda: epub.verify(esig, MSG), runs), sz))
    return res


def device_info():
    info = {"python": sys.version.split()[0], "platform": platform.platform(),
            "machine": platform.machine(), "processor": platform.processor(),
            "liboqs_version": getattr(oqs, "oqs_version", lambda: "unknown")(),
            "liboqs_python_version": getattr(oqs, "oqs_python_version", lambda: "unknown")(),
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        import psutil
        info["cpu_count"] = psutil.cpu_count(logical=True)
        info["ram_total_MB"] = round(psutil.virtual_memory().total / 2**20)
        f = psutil.cpu_freq()
        if f:
            info["cpu_freq_MHz"] = round(f.current)
    except Exception:
        pass
    try:
        with open("/proc/device-tree/model") as fh:
            info["board_model"] = fh.read().strip("\x00\n")
    except OSError:
        pass
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=1000)
    ap.add_argument("--out", default="pqc_results")
    a = ap.parse_args()
    rows = []
    for n in KEMS:
        print("benchmarking", n); rows += bench_kem(n, a.runs)
    for n in SIGS:
        print("benchmarking", n); rows += bench_sig(n, a.runs)
    print("benchmarking classical baselines"); rows += bench_classical(a.runs)

    with open(a.out + ".csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["algorithm", "type", "operation", "median_us", "p95_us", "mean_us", "stdev_us", "min_us", "runs", "sizes"])
        for alg, typ, op, st, sz in rows:
            w.writerow([alg, typ, op, round(st["median_us"], 2), round(st["p95_us"], 2), round(st["mean_us"], 2),
                        round(st["stdev_us"], 2), round(st["min_us"], 2), st["runs"], json.dumps(sz)])
    with open(a.out + "_device.json", "w") as fh:
        json.dump(device_info(), fh, indent=2)
    print(f"\nwrote {a.out}.csv and {a.out}_device.json")
    print(f"{'algorithm':<12}{'op':<10}{'median us':>12}{'p95 us':>12}")
    for alg, typ, op, st, sz in rows:
        print(f"{alg:<12}{op:<10}{st['median_us']:>12.1f}{st['p95_us']:>12.1f}")


if __name__ == "__main__":
    main()
