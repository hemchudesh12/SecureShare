# FILE FORMAT v2: AES-256-GCM, 16MB chunks
# Format per chunk: [4B len][12B nonce][ciphertext+16B GCM tag]
# Legacy CBC files (iv != '') are NOT supported after this change.
# Run migration script before deploying if existing encrypted files exist.

"""
crypto_utils.py — Cryptographic primitives for SecureShare.

Security design:
  • AES-256-GCM (16 MB chunk-based, O(1) RAM) for file encryption
  • Per-chunk 12-byte random nonce; 16-byte GCM authentication tag per chunk
  • RSA-2048 / OAEP  to wrap per-file AES session keys per recipient
  • RSA-2048 / PSS + SHA-256 for sender digital signatures
  • PBKDF2-HMAC-SHA256 + AES-256-CBC for private-key envelope encryption
  • SHA-256 for OTP hashing (compare hashes, never plaintext)
"""

import os
import secrets
import hashlib
import logging
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

logger = logging.getLogger(__name__)

CHUNK_SIZE = 16 * 1024 * 1024  # 16 MB — GCM chunk size
NONCE_SIZE = 12              # 96-bit GCM nonce (NIST recommended)
AES_BLOCK  = 16              # 128-bit block (kept for CBC private-key envelope)
IV_SIZE    = 16              # kept for CBC private-key envelope
PBKDF2_ITERATIONS = 390000  # NIST 2023 recommended minimum for HMAC-SHA256


class CryptoUtils:
    # ──────────────────────────────────────────────────────────────────────
    # OTP Utilities
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def generate_otp() -> str:
        """
        Generate a cryptographically secure 6-digit OTP.
        Uses secrets.randbelow (CSPRNG) — never random.random().
        """
        return f"{secrets.randbelow(1_000_000):06d}"

    @staticmethod
    def hash_otp(otp: str) -> str:
        """
        One-way hash an OTP with SHA-256.
        Stored in DB; plaintext OTP is NEVER stored or logged.
        """
        return hashlib.sha256(otp.encode('utf-8')).hexdigest()

    @staticmethod
    def verify_otp(input_otp: str, stored_hash: str) -> bool:
        """Compare hashes using hmac.compare_digest to prevent timing attacks."""
        import hmac
        input_hash = hashlib.sha256(input_otp.encode('utf-8')).hexdigest()
        return hmac.compare_digest(input_hash, stored_hash)

    # ──────────────────────────────────────────────────────────────────────
    # RSA Key Pair Generation
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def generate_key_pair() -> tuple[bytes, bytes]:
        """Generate RSA-2048 key pair. Returns (private_pem, public_pem) bytes."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem

    # ──────────────────────────────────────────────────────────────────────
    # Private Key Envelope Encryption  (PBKDF2 + AES-256-CBC)
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def encrypt_private_key(private_key_pem: bytes, password: str) -> str:
        """
        Encrypt RSA private key PEM with a key derived from *password*.
        Format stored in DB:  base64(salt) : base64(iv) : base64(ciphertext)
        """
        salt = os.urandom(16)
        kdf  = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        aes_key = kdf.derive(password.encode('utf-8'))

        iv      = os.urandom(IV_SIZE)
        cipher  = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        enc     = cipher.encryptor()
        padder  = PKCS7(128).padder()

        padded    = padder.update(private_key_pem) + padder.finalize()
        ciphertext = enc.update(padded) + enc.finalize()

        return (
            base64.b64encode(salt).decode()       + ':' +
            base64.b64encode(iv).decode()         + ':' +
            base64.b64encode(ciphertext).decode()
        )

    @staticmethod
    def decrypt_private_key(encrypted_bundle: str, password: str) -> bytes:
        """Decrypt the private key envelope. Raises ValueError on wrong password."""
        try:
            salt_b64, iv_b64, ct_b64 = encrypted_bundle.split(':')
            salt       = base64.b64decode(salt_b64)
            iv         = base64.b64decode(iv_b64)
            ciphertext = base64.b64decode(ct_b64)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=PBKDF2_ITERATIONS,
                backend=default_backend()
            )
            aes_key = kdf.derive(password.encode('utf-8'))

            cipher    = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            dec       = cipher.decryptor()
            unpadder  = PKCS7(128).unpadder()

            padded    = dec.update(ciphertext) + dec.finalize()
            plaintext = unpadder.update(padded) + unpadder.finalize()
            return plaintext
        except Exception as exc:
            logger.warning("Private key decryption failed: %s", type(exc).__name__)
            raise ValueError("Invalid password or corrupted key data.")

    # ──────────────────────────────────────────────────────────────────────
    # SHA-256 Streaming Hash
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def compute_sha256_stream(file_path: str) -> bytes:
        h = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.digest()

    # ──────────────────────────────────────────────────────────────────────
    # RSA-PSS Digital Signatures
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def sign_hash(hash_bytes: bytes, private_key_pem: bytes) -> str:
        """Sign a precomputed SHA-256 digest with RSA-PSS. Returns Base64 string."""
        priv = serialization.load_pem_private_key(
            private_key_pem, password=None, backend=default_backend()
        )
        sig = priv.sign(
            hash_bytes,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(sig).decode()

    @staticmethod
    def verify_hash_signature(hash_bytes: bytes, signature_b64: str,
                              public_key_pem: str) -> bool:
        """
        Verify an RSA-PSS signature. Returns True only if the signature is valid.
        Any exception (bad sig, wrong key, corrupted data) returns False.
        """
        try:
            pub = serialization.load_pem_public_key(
                public_key_pem.encode(), backend=default_backend()
            )
            sig = base64.b64decode(signature_b64)
            pub.verify(
                sig,
                hash_bytes,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as exc:
            logger.warning("Signature verification failed: %s", type(exc).__name__)
            return False

    # ──────────────────────────────────────────────────────────────────────
    # AES-256-CBC Chunked File Encryption / Decryption
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def encrypt_file_chunked(src_path: str, dst_path: str) -> tuple[bytes, bytes, bytes]:
        """
        Stream-encrypt *src_path* → *dst_path* using AES-256-GCM in 16 MB chunks.

        File format (v2):
          Per chunk: [4B big-endian (nonce+ciphertext+tag) length][12B nonce][ciphertext+16B GCM tag]

        Returns (aes_key, b'', sha256_of_plaintext).
          • Second element is kept as empty bytes for backward-compatible tuple unpacking.
          • iv is no longer stored per-file; nonces are embedded inline per chunk.
        Memory usage: O(CHUNK_SIZE) regardless of file size.
        """
        aes_key = os.urandom(32)   # AES-256
        sha256  = hashlib.sha256()
        aesgcm  = AESGCM(aes_key)

        with open(src_path, 'rb') as src, open(dst_path, 'wb') as dst:
            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
                nonce      = os.urandom(NONCE_SIZE)
                ciphertext = aesgcm.encrypt(nonce, chunk, None)   # includes 16-byte GCM tag
                payload    = nonce + ciphertext
                dst.write(len(payload).to_bytes(4, 'big'))
                dst.write(payload)

        return aes_key, b'', sha256.digest()

    @staticmethod
    def decrypt_file_chunked(src_path: str, dst_path: str,
                             aes_key: bytes, iv: bytes = b'') -> bytes:
        """
        Stream-decrypt *src_path* → *dst_path* using AES-256-GCM in 16 MB chunks.

        The *iv* parameter is accepted but ignored — nonces are embedded inline
        in the file format and extracted per-chunk (backward-compat signature).

        Raises cryptography.exceptions.InvalidTag if any chunk fails authentication.
        Returns recomputed SHA-256 hash of the recovered plaintext.
        """
        aesgcm = AESGCM(aes_key)
        sha256 = hashlib.sha256()

        with open(src_path, 'rb') as src, open(dst_path, 'wb') as dst:
            while True:
                len_hdr = src.read(4)
                if not len_hdr:
                    break
                ct_len    = int.from_bytes(len_hdr, 'big')
                nonce     = src.read(NONCE_SIZE)
                ciphertext = src.read(ct_len - NONCE_SIZE)
                plaintext  = aesgcm.decrypt(nonce, ciphertext, None)  # raises InvalidTag on failure
                dst.write(plaintext)
                sha256.update(plaintext)

        return sha256.digest()

    # ──────────────────────────────────────────────────────────────────────
    # Streaming Decryption (no plaintext written to disk)
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def compute_plaintext_hash_stream(src_path: str, aes_key: bytes, iv: bytes = b'') -> bytes:
        """
        Decrypt *src_path* in 16 MB GCM chunks and return the SHA-256 hash of
        the recovered plaintext.  NO file is written to disk — decrypted
        bytes are hashed in memory and then discarded.

        The *iv* parameter is accepted but ignored — nonces are embedded inline
        in the file format and extracted per-chunk (backward-compat signature).

        Used to verify the digital signature BEFORE streaming begins.
        Raises cryptography.exceptions.InvalidTag if any chunk fails authentication.
        Memory usage: O(CHUNK_SIZE).
        """
        aesgcm = AESGCM(aes_key)
        sha256 = hashlib.sha256()

        with open(src_path, 'rb') as src:
            while True:
                len_hdr = src.read(4)
                if not len_hdr:
                    break
                ct_len     = int.from_bytes(len_hdr, 'big')
                nonce      = src.read(NONCE_SIZE)
                ciphertext = src.read(ct_len - NONCE_SIZE)
                plaintext  = aesgcm.decrypt(nonce, ciphertext, None)  # raises InvalidTag on failure
                sha256.update(plaintext)

        return sha256.digest()

    @staticmethod
    def stream_decrypt(src_path: str, aes_key: bytes, iv: bytes = b''):
        """
        Generator: decrypt *src_path* chunk-by-chunk using AES-256-GCM and
        yield plaintext bytes directly to the caller (Flask Response iterator).

        The *iv* parameter is accepted but ignored — nonces are embedded inline
        in the file format and extracted per-chunk (backward-compat signature).

        Security guarantees:
          • Each 16 MB chunk is authenticated independently via GCM tag.
          • No plaintext is written to disk at any point.
          • Memory usage: O(CHUNK_SIZE).
          • Raises immediately on authentication failure so Flask terminates
            the connection before more bytes are sent.
        """
        aesgcm = AESGCM(aes_key)

        try:
            with open(src_path, 'rb') as src:
                while True:
                    len_hdr = src.read(4)
                    if not len_hdr:
                        break
                    ct_len     = int.from_bytes(len_hdr, 'big')
                    nonce      = src.read(NONCE_SIZE)
                    ciphertext = src.read(ct_len - NONCE_SIZE)
                    plaintext  = aesgcm.decrypt(nonce, ciphertext, None)  # raises InvalidTag on failure
                    yield plaintext
        except Exception as exc:
            logger.error("stream_decrypt error: %s", exc)
            raise

    # ──────────────────────────────────────────────────────────────────────
    # RSA Key Wrapping (OAEP) — encrypt/decrypt AES session key
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def encrypt_aes_key(aes_key: bytes, public_key_pem: str) -> bytes:
        pub = serialization.load_pem_public_key(
            public_key_pem.encode(), backend=default_backend()
        )
        return pub.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def decrypt_aes_key(encrypted_aes_key: bytes, private_key_pem: bytes) -> bytes:
        priv = serialization.load_pem_private_key(
            private_key_pem, password=None, backend=default_backend()
        )
        return priv.decrypt(
            encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
