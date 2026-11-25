"""
hash_utils.py
Fungsi-fungsi bantu untuk menghitung hash dan mendeteksi kemungkinan
algoritma hash berdasarkan panjang string hex-nya.

Tujuan project ini murni edukasi: memahami bagaimana hash satu-arah
bekerja, mengapa dictionary/brute-force attack bisa berhasil pada
password yang lemah, dan mengapa salting + algoritma lambat (bcrypt,
scrypt, argon2) penting untuk keamanan password di dunia nyata.
"""

from __future__ import annotations
import hashlib
from typing import Optional


# Algoritma hash yang didukung. Semua ini stdlib, tanpa dependency luar.
SUPPORTED_ALGORITHMS = (
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
)

# Panjang output (dalam karakter hex) untuk masing-masing algoritma.
# Dipakai untuk menebak algoritma dari sebuah hash yang tidak diketahui.
_HASH_LENGTHS = {
    32: ["md5"],
    40: ["sha1"],
    56: ["sha224"],
    64: ["sha256"],
    96: ["sha384"],
    128: ["sha512"],
}


def compute_hash(text: str, algorithm: str, salt: str = "") -> str:
    """Hitung hash hex dari `text` (+ salt opsional) memakai `algorithm`.

    Salt ditambahkan di akhir plaintext: hash(password + salt).
    Ini hanya skema sederhana untuk demonstrasi; skema produksi
    sesungguhnya memakai algoritma khusus password (bcrypt/argon2).
    """
    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Algoritma tidak didukung: {algorithm}")

    hasher = hashlib.new(algorithm)
    hasher.update((text + salt).encode("utf-8"))
    return hasher.hexdigest()


def identify_hash(hash_string: str) -> list[str]:
    """Tebak kemungkinan algoritma dari sebuah hash hex berdasarkan panjang.

    Ini BUKAN deteksi pasti (banyak algoritma berbeda bisa punya panjang
    output yang sama, mis. SHA3-256 vs SHA256), hanya heuristik panjang.
    """
    hash_string = hash_string.strip()
    if not _is_hex(hash_string):
        return []
    return _HASH_LENGTHS.get(len(hash_string), [])


def _is_hex(s: str) -> bool:
    if not s:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def looks_like_hash(s: str) -> bool:
    """Cek cepat apakah string tampak seperti hash hex yang valid."""
    return _is_hex(s) and len(s) in _HASH_LENGTHS
