"""
cracker.py
Logika inti hash cracking: dictionary attack dan brute-force attack,
dengan dukungan multithreading agar lebih cepat pada CPU multi-core.
"""

from __future__ import annotations
import itertools
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Optional

from .hash_utils import compute_hash
from .wordlist import load_wordlist


@dataclass
class CrackResult:
    found: bool
    plaintext: Optional[str]
    attempts: int
    elapsed_seconds: float
    method: str


def dictionary_attack(
    target_hash: str,
    algorithm: str,
    wordlist_path: str,
    salt: str = "",
    workers: int = 4,
    on_progress: Optional[Callable[[int], None]] = None,
) -> CrackResult:
    """Coba cocokkan target_hash dengan hash dari setiap kata di wordlist.

    `workers` > 1 memakai thread pool untuk menghitung hash secara paralel
    dalam batch, mempercepat proses pada wordlist besar.
    """
    target_hash = target_hash.strip().lower()
    start = time.perf_counter()
    attempts = 0

    def check(word: str) -> Optional[str]:
        if compute_hash(word, algorithm, salt) == target_hash:
            return word
        return None

    words = load_wordlist(wordlist_path)
    batch_size = max(workers * 200, 200)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        while True:
            batch = list(itertools.islice(words, batch_size))
            if not batch:
                break

            futures = {pool.submit(check, w): w for w in batch}
            for future in as_completed(futures):
                attempts += 1
                result = future.result()
                if result is not None:
                    # Batalkan sisa pekerjaan di batch ini & keluar.
                    for f in futures:
                        f.cancel()
                    elapsed = time.perf_counter() - start
                    return CrackResult(True, result, attempts, elapsed, "dictionary")

            if on_progress:
                on_progress(attempts)

    elapsed = time.perf_counter() - start
    return CrackResult(False, None, attempts, elapsed, "dictionary")


def brute_force_attack(
    target_hash: str,
    algorithm: str,
    salt: str = "",
    charset: str = string.ascii_lowercase + string.digits,
    min_length: int = 1,
    max_length: int = 5,
    on_progress: Optional[Callable[[int], None]] = None,
) -> CrackResult:
    """Coba semua kombinasi karakter dari min_length sampai max_length.

    PERINGATAN: ruang pencarian tumbuh secara eksponensial
    (len(charset) ** panjang), jadi brute-force hanya praktis untuk
    password pendek. Ini sengaja dibuat demonstratif, bukan dioptimasi
    untuk kecepatan produksi (lihat hashcat/John the Ripper untuk itu).
    """
    target_hash = target_hash.strip().lower()
    start = time.perf_counter()
    attempts = 0

    for length in range(min_length, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            attempts += 1

            if compute_hash(candidate, algorithm, salt) == target_hash:
                elapsed = time.perf_counter() - start
                return CrackResult(True, candidate, attempts, elapsed, "brute_force")

            if on_progress and attempts % 50_000 == 0:
                on_progress(attempts)

    elapsed = time.perf_counter() - start
    return CrackResult(False, None, attempts, elapsed, "brute_force")
