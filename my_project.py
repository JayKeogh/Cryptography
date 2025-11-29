#!/usr/bin/env python3

# Student Name: Jay Keogh
# Student ID: C00300208
# Date: 21/11/2025
# Cryptography Benchmark
# -----------------------------------------

# This program performs timing benchmarks for a selection of
# cryptographic operations. The goal is to measure the performance
# of algorithms across different security strengths and produce
# CSV outputs usable for analysis or report preparation.

# The script evaluates:
# - Symmetric ciphers (AES-GCM, ChaCha20-Poly1305)
# - Public-key encryption (RSA-OAEP)
# - Digital signatures (RSA-PSS, DSA, ECDSA)
# - Key generation costs for RSA, DSA and ECC

# All metrics are logged to CSV files under the "results" directory.

# -----------------------------------------
# Test System Information:
# CPU: 11th Gen Intel Core i5-11400H @ 2.70GHz
# RAM: 8GB DDR4
# OS: Windows 11 Home
# Python: 3.12.6
# cryptography package version: 46.0.3
# -----------------------------------------

import os
import time
import csv
from pathlib import Path
import statistics

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

import pandas as pd
import matplotlib.pyplot as plt

# ----------------- SETTINGS -----------------

# Number of test iterations (first run is treated as a warm-up)
N_RUNS = 10

# Size of plaintext buffer used in symmetric cipher tests (10 KiB)
PLAINTEXT_SIZE = 10 * 1024

# Directory where CSV files should be written
OUT_DIR = Path("results")
OUT_DIR.mkdir(exist_ok=True)

# Security levels referenced throughout the benchmarking suite
SECURITY_LEVELS = [80, 112, 128, 192, 256]

# RSA modulus sizes aligned with typical security equivalences
RSA_KEY_SIZES = {
    80: 1024,
    112: 2048,
    128: 3072,
    192: 4096,
    256: 8192,
}

# DSA key lengths comparable to traditional security categories
DSA_KEY_SIZES = {
    80: 1024,
    112: 2048,
    128: 3072,
    192: None,
    256: None,
}

# Elliptic curves matching standard strength levels
ECC_CURVES = {
    80: ec.SECP192R1(),
    112: ec.SECP224R1(),
    128: ec.SECP256R1(),
    192: ec.SECP384R1(),
    256: ec.SECP521R1(),
}

# AES supported key sizes (in bits)
AES_KEY_SIZES = [128, 192, 256]


# ----------------- UTILITY FUNCTIONS -----------------

def mean_excluding_first(values):
    """Calculate the mean of all values except the first warm-up entry."""
    values = [v for v in values if v is not None]
    if len(values) <= 1:
        return None
    return statistics.mean(values[1:])


def time_function(fn, *args, **kwargs):
    """Measure execution time of a provided function call."""
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    t1 = time.perf_counter()
    return result, (t1 - t0)


def print_table(headers, rows):
    """
    Output results as a neatly aligned table in the console.
    :param headers: column titles
    :param rows:    list of table rows
    """
    if not rows:
        return

    str_rows = [[str(c) for c in row] for row in rows]
    widths = [len(h) for h in headers]

    for row in str_rows:
        for i, val in enumerate(row):
            widths[i] = max(widths[i], len(val))

    fmt = " | ".join(f"{{:<{w}}}" for w in widths)

    print("-" * (sum(widths) + 3 * (len(widths) - 1)))
    print(fmt.format(*headers))
    print("-" * (sum(widths) + 3 * (len(widths) - 1)))

    for row in str_rows:
        print(fmt.format(*row))

    print("-" * (sum(widths) + 3 * (len(widths) - 1)))
    print()


# ----------------- KEY GENERATION BENCHMARK -----------------

def bench_keygen():
    """
    Measure the time required to generate RSA, DSA, and ECC key pairs.
    Results are saved to keygen_results.csv.
    """
    rows = []

    for sec in SECURITY_LEVELS:
        # RSA key creation timing
        rsa_size = RSA_KEY_SIZES.get(sec)
        if rsa_size:
            times = []
            for i in range(N_RUNS):
                try:
                    _, t = time_function(
                        rsa.generate_private_key,
                        public_exponent=65537,
                        key_size=rsa_size
                    )
                except Exception as e:
                    print(f"[!] RSA {rsa_size} key creation error: {e}")
                    t = None
                times.append(t)
                rows.append(["RSA", sec, rsa_size, i+1, t])
            mean_excluding_first(times)

        # DSA key generation timing
        dsa_size = DSA_KEY_SIZES.get(sec)
        if dsa_size:
            times = []
            for i in range(N_RUNS):
                try:
                    _, t = time_function(dsa.generate_private_key, key_size=dsa_size)
                except Exception as e:
                    print(f"[!] DSA {dsa_size} key creation error: {e}")
                    t = None
                times.append(t)
                rows.append(["DSA", sec, dsa_size, i+1, t])
            mean_excluding_first(times)

        # ECC key generation timing
        curve = ECC_CURVES.get(sec)
        if curve:
            times = []
            for i in range(N_RUNS):
                try:
                    _, t = time_function(ec.generate_private_key, curve)
                except Exception as e:
                    print(f"[!] ECC {curve.name} key creation error: {e}")
                    t = None
                times.append(t)
                rows.append(["ECC", sec, curve.name, i+1, t])
            mean_excluding_first(times)

    # Write CSV output
    file = OUT_DIR / "keygen_results.csv"
    with file.open("w", newline="") as f:
        w = csv.writer(f)
        header = ["algorithm", "security_bits", "param"] + [f"run_{i+1}" for i in range(N_RUNS)] + ["average_time"]
        w.writerow(header)

        from collections import defaultdict
        grouped_data = defaultdict(list)

        for alg, sec, param, run, t in rows:
            grouped_data[(alg, sec, param)].append(t)

        table_rows = []

        for (alg, sec, param), times in grouped_data.items():
            avg = mean_excluding_first(times)
            row = [alg, sec, param] + [("" if t is None else f"{t:.6f}") for t in times] + [("" if avg is None else f"{avg:.6f}")]
            w.writerow(row)
            table_rows.append([alg, sec, param, f"{avg:.6f}s" if avg else "Failed"])

    print(f"[+] Key generation benchmark complete -> {file}")
    print_table(["Algorithm", "Security Level", "Parameter", "Avg Time"], table_rows)


# ----------------- SYMMETRIC CIPHER BENCHMARK -----------------

def bench_symmetric():
    """
    Benchmark AES-GCM and ChaCha20-Poly1305 performance for
    both encryption and decryption. Output saved to symmetric_results.csv.
    """
    rows = []
    plaintext = os.urandom(PLAINTEXT_SIZE)

    # AES-GCM tests
    for key_bits in AES_KEY_SIZES:
        key_bytes = key_bits // 8
        aes_key = os.urandom(key_bytes)
        aesgcm = AESGCM(aes_key)

        enc_times = []
        dec_times = []

        for i in range(N_RUNS):
            nonce = os.urandom(12)

            def do_encrypt():
                return aesgcm.encrypt(nonce, plaintext, None)

            ct, t_enc = time_function(do_encrypt)

            def do_decrypt():
                return aesgcm.decrypt(nonce, ct, None)

            pt, t_dec = time_function(do_decrypt)
            assert pt == plaintext

            enc_times.append(t_enc)
            dec_times.append(t_dec)

            rows.append(["AES-GCM", key_bits, "encrypt", i+1, t_enc])
            rows.append(["AES-GCM", key_bits, "decrypt", i+1, t_dec])

    # ChaCha20-Poly1305 tests
    ch_key = os.urandom(32)
    ch = ChaCha20Poly1305(ch_key)

    enc_times = []
    dec_times = []

    for i in range(N_RUNS):
        nonce = os.urandom(12)

        def do_encrypt():
            return ch.encrypt(nonce, plaintext, None)

        ct, t_enc = time_function(do_encrypt)

        def do_decrypt():
            return ch.decrypt(nonce, ct, None)

        pt, t_dec = time_function(do_decrypt)
        assert pt == plaintext

        rows.append(["ChaCha20-Poly1305", 256, "encrypt", i+1, t_enc])
        rows.append(["ChaCha20-Poly1305", 256, "decrypt", i+1, t_dec])

    # Write CSV
    file = OUT_DIR / "symmetric_results.csv"
    with file.open("w", newline="") as f:
        w = csv.writer(f)
        header = ["algorithm", "key_bits", "operation"] + [f"run_{i+1}" for i in range(N_RUNS)] + ["average_time"]
        w.writerow(header)

        from collections import defaultdict
        grouped_data = defaultdict(list)

        for alg, key_bits, op, run, t in rows:
            grouped_data[(alg, key_bits, op)].append(t)

        table_rows = []

        for (alg, key_bits, op), times in grouped_data.items():
            avg = mean_excluding_first(times)
            row = [alg, key_bits, op] + [f"{t:.6f}" for t in times] + [f"{avg:.6f}"]
            w.writerow(row)
            table_rows.append([alg, key_bits, op, f"{avg:.6f}s"])

    print(f"[+] Symmetric cipher benchmark complete -> {file}")
    print_table(["Algorithm", "Key Size", "Op", "Avg Time"], table_rows)


# ----------------- RSA ENCRYPTION BENCHMARK -----------------

def bench_rsa_encryption():
    """
    Benchmark RSA encryption & decryption using OAEP padding.
    Each supported key size is evaluated. Results saved to rsa_enc_results.csv.
    """
    rows = []
    message = os.urandom(32)  # fits within the OAEP constraints for all key sizes

    for sec in SECURITY_LEVELS:
        key_size = RSA_KEY_SIZES.get(sec)
        if not key_size:
            continue

        try:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        except Exception as e:
            print(f"[!] RSA-{key_size} key creation failure: {e}")
            continue

        public_key = private_key.public_key()

        enc_times = []
        dec_times = []

        for i in range(N_RUNS):

            def do_encrypt():
                return public_key.encrypt(
                    message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

            try:
                ct, t_enc = time_function(do_encrypt)
            except ValueError as e:
                print(f"[!] RSA-{key_size} encryption failed on run {i+1}: {e}")
                rows = [r for r in rows if not (r[0] == "RSA-OAEP" and r[1] == key_size)]
                break

            def do_decrypt():
                return private_key.decrypt(
                    ct,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

            pt, t_dec = time_function(do_decrypt)
            assert pt == message

            rows.append(["RSA-OAEP", key_size, "encrypt", i+1, t_enc])
            rows.append(["RSA-OAEP", key_size, "decrypt", i+1, t_dec])

        if not rows:
            print(f"[!] Skipped RSA {key_size}: encryption error encountered")

    # Write CSV
    file = OUT_DIR / "rsa_enc_results.csv"
    with file.open("w", newline="") as f:
        w = csv.writer(f)
        header = ["algorithm", "key_bits", "operation"] + [f"run_{i+1}" for i in range(N_RUNS)] + ["average_time"]
        w.writerow(header)

        from collections import defaultdict
        grouped_data = defaultdict(list)

        for alg, bits, op, run, t in rows:
            grouped_data[(alg, bits, op)].append(t)

        table_rows = []

        for (alg, bits, op), times in grouped_data.items():
            avg = mean_excluding_first(times)
            row = [alg, bits, op] + [f"{t:.6f}" for t in times] + [f"{avg:.6f}"]
            w.writerow(row)
            table_rows.append([alg, bits, op, f"{avg:.6f}s"])

    print(f"[+] RSA-OAEP benchmark complete -> {file}")
    print_table(["Algorithm", "Key Size", "Op", "Avg Time"], table_rows)


# ----------------- SIGNATURE BENCHMARK -----------------

def bench_signatures():
    """
    Benchmark signing and verification workloads for:
    - RSA-PSS
    - DSA
    - ECDSA
    Output saved to signature_results.csv.
    """
    rows = []
    message = os.urandom(128)

    for sec in SECURITY_LEVELS:
        # RSA-PSS
        rsa_size = RSA_KEY_SIZES.get(sec)
        if rsa_size:
            try:
                rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=rsa_size)
            except Exception as e:
                print(f"[!] RSA {rsa_size} keygen error (signature tests): {e}")
                rsa_priv = None

            if rsa_priv:
                rsa_pub = rsa_priv.public_key()
                for i in range(N_RUNS):
                    def do_sign():
                        return rsa_priv.sign(
                            message,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH,
                            ),
                            hashes.SHA256(),
                        )

                    sig, t_sign = time_function(do_sign)

                    def do_verify():
                        rsa_pub.verify(
                            sig,
                            message,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH,
                            ),
                            hashes.SHA256(),
                        )

                    _, t_verify = time_function(do_verify)

                    rows.append(["RSA-PSS", rsa_size, "sign", i+1, t_sign])
                    rows.append(["RSA-PSS", rsa_size, "verify", i+1, t_verify])

        # DSA
        dsa_size = DSA_KEY_SIZES.get(sec)
        if dsa_size:
            try:
                dsa_priv = dsa.generate_private_key(key_size=dsa_size)
            except Exception as e:
                print(f"[!] DSA {dsa_size} keygen issue (signature tests): {e}")
                dsa_priv = None

            if dsa_priv:
                dsa_pub = dsa_priv.public_key()
                for i in range(N_RUNS):
                    def do_sign():
                        return dsa_priv.sign(message, hashes.SHA256())

                    sig, t_sign = time_function(do_sign)

                    def do_verify():
                        dsa_pub.verify(sig, message, hashes.SHA256())

                    _, t_verify = time_function(do_verify)

                    rows.append(["DSA", dsa_size, "sign", i+1, t_sign])
                    rows.append(["DSA", dsa_size, "verify", i+1, t_verify])

        # ECDSA
        curve = ECC_CURVES.get(sec)
        if curve:
            try:
                ecc_priv = ec.generate_private_key(curve)
            except Exception as e:
                print(f"[!] ECC {curve.name} keygen failure (signature tests): {e}")
                ecc_priv = None

            if ecc_priv:
                ecc_pub = ecc_priv.public_key()
                for i in range(N_RUNS):
                    def do_sign():
                        return ecc_priv.sign(message, ec.ECDSA(hashes.SHA256()))

                    sig, t_sign = time_function(do_sign)

                    def do_verify():
                        ecc_pub.verify(sig, message, ec.ECDSA(hashes.SHA256()))

                    _, t_verify = time_function(do_verify)

                    rows.append(["ECDSA", curve.name, "sign", i+1, t_sign])
                    rows.append(["ECDSA", curve.name, "verify", i+1, t_verify])

    # Write CSV
    file = OUT_DIR / "signature_results.csv"
    with file.open("w", newline="") as f:
        w = csv.writer(f)
        header = ["algorithm", "param", "operation"] + [f"run_{i+1}" for i in range(N_RUNS)] + ["average_time"]
        w.writerow(header)

        from collections import defaultdict
        grouped_data = defaultdict(list)

        for alg, param, op, run, t in rows:
            grouped_data[(alg, param, op)].append(t)

        table_rows = []

        for (alg, param, op), times in grouped_data.items():
            avg = mean_excluding_first(times)
            row = [alg, param, op] + [f"{t:.6f}" for t in times] + [f"{avg:.6f}"]
            w.writerow(row)
            table_rows.append([alg, param, op, f"{avg:.6f}s"])

    print(f"[+] Digital signature benchmark complete -> {file}")
    print_table(["Algorithm", "Parameter", "Op", "Avg Time"], table_rows)


# ----------------- PLOTTING FUNCTIONS -----------------

def load_csv(name):
    return pd.read_csv(OUT_DIR / name)

def save_fig(name):
    out = OUT_DIR / name
    plt.tight_layout()
    plt.savefig(out, dpi=300)
    plt.close()
    print(f"Saved plot to {out}")

def plot_keygen():
    df = load_csv("keygen_results.csv")
    df = df.dropna(subset=["average_time"])
    df["time_ms"] = df["average_time"] * 1000

    # grp is no longer needed as df is already grouped
    grp = df

    plt.figure()
    for alg in ["RSA", "DSA", "ECC"]:
        sub = grp[grp["algorithm"] == alg]
        if not sub.empty:
            plt.plot(sub["security_bits"], sub["time_ms"], marker="o", label=alg)

    plt.yscale("log")
    plt.xlabel("Security level (bits)")
    plt.ylabel("Time (ms) — log scale")
    plt.title("Key Pair Generation")
    plt.grid(True, which="both", linestyle="--")
    plt.legend()
    save_fig("plot_keygen.png")

def plot_symmetric():
    df = load_csv("symmetric_results.csv")
    df = df.dropna(subset=["average_time"])
    df["time_ms"] = df["average_time"] * 1000

    # Encryption
    enc = df[df["operation"] == "encrypt"]
    plt.figure()
    for alg in enc["algorithm"].unique():
        sub = enc[enc["algorithm"] == alg]
        plt.plot(sub["key_bits"], sub["time_ms"], marker="o", label=alg)

    plt.xlabel("Key size (bits)")
    plt.ylabel("Time (ms)")
    plt.title("Symmetric Encryption (AES & ChaCha20)")
    plt.grid(True, linestyle="--")
    plt.legend()
    save_fig("plot_symmetric_enc.png")

    # Decryption
    dec = df[df["operation"] == "decrypt"]
    plt.figure()
    for alg in dec["algorithm"].unique():
        sub = dec[dec["algorithm"] == alg]
        plt.plot(sub["key_bits"], sub["time_ms"], marker="o", label=alg)

    plt.xlabel("Key size (bits)")
    plt.ylabel("Time (ms)")
    plt.title("Symmetric Decryption (AES & ChaCha20)")
    plt.grid(True, linestyle="--")
    plt.legend()
    save_fig("plot_symmetric_dec.png")

def plot_rsa_enc():
    df = load_csv("rsa_enc_results.csv")
    df = df.dropna(subset=["average_time"])
    df["time_ms"] = df["average_time"] * 1000

    enc = df[df["operation"] == "encrypt"]
    dec = df[df["operation"] == "decrypt"]

    plt.figure()
    plt.plot(enc["key_bits"], enc["time_ms"], marker="o", label="Encrypt")
    plt.plot(dec["key_bits"], dec["time_ms"], marker="s", label="Decrypt")

    plt.xlabel("RSA key size (bits)")
    plt.ylabel("Time (ms)")
    plt.title("RSA Encryption & Decryption")
    plt.grid(True, linestyle="--")
    plt.legend()
    save_fig("plot_rsa_enc_dec.png")

def plot_signatures():
    df = load_csv("signature_results.csv")
    df = df.dropna(subset=["average_time"])
    df["time_ms"] = df["average_time"] * 1000

    df = df.sort_values(by=["algorithm", "param"])

    for op in ["sign", "verify"]:
        sub = df[df["operation"] == op]

        plt.figure()
        for alg in sub["algorithm"].unique():
            means = sub[sub["algorithm"] == alg]

            plt.plot(
                means["param"],
                means["time_ms"],
                marker="o",
                label=alg
            )

        plt.xlabel("Security level (param)")
        plt.ylabel("Time (ms)")
        plt.title(f"Digital Signatures — {op.capitalize()}")
        plt.grid(True, linestyle="--")
        plt.legend()

        save_fig(f"plot_signatures_{op}.png")


# ----------------- MAIN -----------------

def main():
    """
    Execute all benchmark categories in sequence.
    All resulting measurements are exported to CSV files
    inside the 'results/' folder.
    """
    print("Key Generation Benchmarks")
    bench_keygen()

    print("\nSymmetric Cipher Benchmarks")
    bench_symmetric()

    print("\nRSA Encryption Benchmarks")
    bench_rsa_encryption()

    print("\nDigital Signature Benchmarks")
    bench_signatures()

    print("\nBenchmarking complete. Output stored in the 'results/' directory.")
    
    print("\nGenerating plots...")
    plot_keygen()
    plot_symmetric()
    plot_rsa_enc()
    plot_signatures()
    print("All plots generated successfully!")


if __name__ == "__main__":
    main()
