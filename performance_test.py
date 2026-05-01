"""
performance_test.py — Benchmark for chunk-based AES-256-CBC I/O.

Tests encrypt_file_chunked + decrypt_file_chunked on a synthetic 1 GB file.
Measures:
  - Wall-clock time for encryption and decryption
  - Peak memory allocation (via tracemalloc) — should stay near CHUNK_SIZE
  - Throughput in MB/s
  - SHA-256 hash round-trip correctness

Usage (no server needed):
    python performance_test.py

Memory expectation:
    Peak RSS will be dominated by Python interpreter overhead (~20–30 MB).
    The tracemalloc peak for the encrypt/decrypt calls themselves should be
    well under 2 MB regardless of the 1 GB file size because only 64 KB
    chunks are ever live in memory at once.
"""

import os
import sys
import time
import tracemalloc
import tempfile

# ---------------------------------------------------------------------------
# Bootstrap: make sure we can import from the project directory
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(__file__))
from crypto_utils import CryptoUtils, CHUNK_SIZE   # noqa: E402

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

FILE_SIZE_GB  = 1          # target synthetic file size
FILE_SIZE     = FILE_SIZE_GB * 1024 * 1024 * 1024   # bytes
WRITE_CHUNK   = 64 * 1024 * 1024                    # write 64 MB at a time


def hr(label: str):
    print(f"\n{'─' * 60}")
    print(f"  {label}")
    print('─' * 60)


def format_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


# ---------------------------------------------------------------------------
# Step 1 — Create a synthetic 1 GB plaintext file
# ---------------------------------------------------------------------------

def create_synthetic_file(path: str, size: int):
    """Write *size* bytes of pseudo-random data to *path* in WRITE_CHUNK slices."""
    written = 0
    with open(path, 'wb') as f:
        while written < size:
            chunk = os.urandom(min(WRITE_CHUNK, size - written))
            f.write(chunk)
            written += len(chunk)
    print(f"  Created synthetic file: {format_size(size)} at {path}")


# ---------------------------------------------------------------------------
# Step 2 — Benchmark helper
# ---------------------------------------------------------------------------

def benchmark(label: str, fn, *args, **kwargs):
    """
    Run *fn(*args, **kwargs)*, measuring wall time and tracemalloc peak.
    Returns whatever *fn* returns.
    """
    tracemalloc.start()
    t0  = time.perf_counter()

    result = fn(*args, **kwargs)

    elapsed = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    throughput = (FILE_SIZE / elapsed) / (1024 * 1024)   # MB/s

    print(f"  {label}")
    print(f"    Time:       {elapsed:.2f}s")
    print(f"    Throughput: {throughput:.1f} MB/s")
    print(f"    Peak mem (tracemalloc): {format_size(peak)}")

    return result


# ---------------------------------------------------------------------------
# Step 3 — Correctness check
# ---------------------------------------------------------------------------

def verify_round_trip(src_hash: bytes, dec_path: str) -> bool:
    dec_hash = CryptoUtils.compute_sha256_stream(dec_path)
    match    = (src_hash == dec_hash)
    status   = "✅ MATCH" if match else "❌ MISMATCH"
    print(f"  SHA-256 round-trip: {status}")
    print(f"    Original:   {src_hash.hex()}")
    print(f"    Decrypted:  {dec_hash.hex()}")
    return match


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print(f"  SecureShare — Chunk-Based AES-256-CBC Performance Test")
    print(f"  File size : {FILE_SIZE_GB} GB")
    print(f"  Chunk size: {format_size(CHUNK_SIZE)}")
    print("=" * 60)

    # Use system temp dir for large I/O
    tmp_dir = tempfile.gettempdir()

    src_path = os.path.join(tmp_dir, "perf_plaintext.bin")
    enc_path = os.path.join(tmp_dir, "perf_encrypted.bin")
    dec_path = os.path.join(tmp_dir, "perf_decrypted.bin")

    try:
        # -- Create plaintext --------------------------------------------------
        hr("STEP 1 — Creating synthetic 1 GB plaintext file")
        create_synthetic_file(src_path, FILE_SIZE)

        # -- Hash plaintext (baseline; also tests O(1) streaming hash) ---------
        hr("STEP 2 — SHA-256 streaming hash of plaintext (baseline)")
        src_hash = benchmark("compute_sha256_stream(src)",
                             CryptoUtils.compute_sha256_stream, src_path)

        # -- Encryption --------------------------------------------------------
        hr("STEP 3 — encrypt_file_chunked (AES-256-CBC, 64 KB chunks)")
        iv, aes_key = benchmark("encrypt_file_chunked(src → enc)",
                                CryptoUtils.encrypt_file_chunked,
                                src_path, enc_path)

        enc_size = os.path.getsize(enc_path)
        print(f"  Encrypted file size: {format_size(enc_size)}  "
              f"(overhead: {(enc_size - FILE_SIZE)} bytes = IV + PKCS7 pad)")

        # -- Decryption --------------------------------------------------------
        hr("STEP 4 — decrypt_file_chunked (AES-256-CBC, 64 KB chunks)")
        benchmark("decrypt_file_chunked(enc → dec)",
                  CryptoUtils.decrypt_file_chunked,
                  enc_path, dec_path, aes_key, iv)

        # -- Correctness -------------------------------------------------------
        hr("STEP 5 — Round-trip correctness check")
        ok = verify_round_trip(src_hash, dec_path)

        # -- Summary -----------------------------------------------------------
        print("\n" + "=" * 60)
        if ok:
            print("  ✅  ALL STEPS PASSED — Chunk-based streaming works correctly")
        else:
            print("  ❌  HASH MISMATCH — Round-trip correctness FAILED")
        print("=" * 60)

        print("\nMemory model explanation")
        print("  Only ONE 64KB chunk is live in Python memory at a time.")
        print("  The tracemalloc 'peak' above reflects encrypt/decrypt call frames")
        print("  plus tiny PKCS7 / cipher context buffers — NOT the file size.")
        print("  This means: memory usage is O(CHUNK_SIZE) = O(64 KB), constant")
        print("  regardless of whether you encrypt a 10 MB or a 100 GB file.\n")

    finally:
        for path in (src_path, enc_path, dec_path):
            try:
                os.remove(path)
            except OSError:
                pass
        print("  Temp files cleaned up.")


if __name__ == "__main__":
    main()
