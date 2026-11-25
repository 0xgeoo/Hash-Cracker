"""
wordlist.py
Memuat daftar kata (wordlist) dari file teks untuk dictionary attack.
"""

from __future__ import annotations
from pathlib import Path
from typing import Iterator


def load_wordlist(path: str) -> Iterator[str]:
    """Generator yang membaca wordlist baris per baris.

    Memakai generator (bukan list) supaya wordlist besar (jutaan baris,
    mis. rockyou.txt) tidak perlu dimuat sekaligus ke memori.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Wordlist tidak ditemukan: {path}")

    with file_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.rstrip("\n\r")
            if word:
                yield word


def count_lines(path: str) -> int:
    """Hitung jumlah baris non-kosong dalam wordlist (untuk progress bar)."""
    return sum(1 for _ in load_wordlist(path))
