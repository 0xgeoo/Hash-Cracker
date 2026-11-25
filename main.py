#!/usr/bin/env python3
"""
Hash Cracker - CLI
===================
Tool edukasi untuk memahami dictionary attack & brute-force attack
terhadap hash satu-arah (MD5, SHA1, SHA-2 family).

Contoh pemakaian:
  # Hitung hash dari sebuah kata (untuk membuat target uji coba)
  python main.py hash --text "password123" --algo sha256

  # Dictionary attack
  python main.py crack --hash <hash_hex> --algo sha256 --wordlist wordlists/common_passwords.txt

  # Brute-force attack
  python main.py crack --hash <hash_hex> --algo md5 --mode bruteforce --max-length 4

  # Identifikasi kemungkinan algoritma dari sebuah hash
  python main.py identify --hash <hash_hex>

PERINGATAN ETIKA:
Gunakan tool ini HANYA pada hash milik Anda sendiri, data uji (lab/CTF),
atau sistem yang Anda memiliki izin eksplisit untuk diuji. Meng-crack
kredensial orang lain tanpa izin adalah ilegal di hampir semua yurisdiksi.
"""

from __future__ import annotations
import argparse
import string
import sys

from hash_cracker.hash_utils import compute_hash, identify_hash, SUPPORTED_ALGORITHMS
from hash_cracker.cracker import dictionary_attack, brute_force_attack
from hash_cracker.wordlist import count_lines


CHARSETS = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "letters": string.ascii_letters,
    "digits": string.digits,
    "alnum": string.ascii_letters + string.digits,
    "all": string.ascii_letters + string.digits + string.punctuation,
}


def cmd_hash(args: argparse.Namespace) -> int:
    result = compute_hash(args.text, args.algo, args.salt)
    print(f"[{args.algo}] {args.text!r} (+salt={args.salt!r}) -> {result}")
    return 0


def cmd_identify(args: argparse.Namespace) -> int:
    candidates = identify_hash(args.hash)
    if not candidates:
        print("Tidak ada algoritma yang cocok berdasarkan panjang hash.")
        return 1
    print(f"Hash sepanjang {len(args.hash.strip())} karakter hex.")
    print("Kemungkinan algoritma:", ", ".join(candidates))
    print("(Heuristik berdasarkan panjang saja, bukan deteksi pasti.)")
    return 0


def cmd_crack(args: argparse.Namespace) -> int:
    print(f"Target hash : {args.hash}")
    print(f"Algoritma   : {args.algo}")
    print(f"Mode        : {args.mode}")
    print("-" * 50)

    if args.mode == "dictionary":
        if not args.wordlist:
            print("Error: --wordlist wajib diisi untuk mode dictionary.")
            return 1

        total = count_lines(args.wordlist)
        print(f"Wordlist    : {args.wordlist} ({total:,} kata)")

        def progress(attempts: int) -> None:
            pct = (attempts / total * 100) if total else 0
            print(f"\r  Mencoba... {attempts:,}/{total:,} ({pct:.1f}%)", end="", flush=True)

        result = dictionary_attack(
            args.hash, args.algo, args.wordlist,
            salt=args.salt, workers=args.workers, on_progress=progress,
        )
        print()

    else:  # bruteforce
        charset = CHARSETS.get(args.charset, args.charset)
        print(f"Charset     : {args.charset} ({len(charset)} karakter)")
        print(f"Panjang     : {args.min_length} - {args.max_length}")

        def progress(attempts: int) -> None:
            print(f"\r  Mencoba... {attempts:,} kombinasi", end="", flush=True)

        result = brute_force_attack(
            args.hash, args.algo,
            salt=args.salt, charset=charset,
            min_length=args.min_length, max_length=args.max_length,
            on_progress=progress,
        )
        print()

    print("-" * 50)
    if result.found:
        print(f"✅ DITEMUKAN: {result.plaintext!r}")
    else:
        print("❌ Tidak ditemukan dalam ruang pencarian yang diberikan.")
    print(f"Percobaan   : {result.attempts:,}")
    print(f"Waktu       : {result.elapsed_seconds:.3f} detik")
    if result.elapsed_seconds > 0:
        rate = result.attempts / result.elapsed_seconds
        print(f"Kecepatan   : {rate:,.0f} hash/detik")

    return 0 if result.found else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Hash Cracker - tool edukasi dictionary & brute-force attack",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # hash
    p_hash = sub.add_parser("hash", help="Hitung hash dari sebuah teks")
    p_hash.add_argument("--text", required=True, help="Teks/plaintext yang akan di-hash")
    p_hash.add_argument("--algo", default="sha256", choices=SUPPORTED_ALGORITHMS)
    p_hash.add_argument("--salt", default="", help="Salt opsional (ditambahkan di akhir)")
    p_hash.set_defaults(func=cmd_hash)

    # identify
    p_id = sub.add_parser("identify", help="Tebak algoritma dari sebuah hash")
    p_id.add_argument("--hash", required=True)
    p_id.set_defaults(func=cmd_identify)

    # crack
    p_crack = sub.add_parser("crack", help="Jalankan serangan terhadap sebuah hash")
    p_crack.add_argument("--hash", required=True, help="Hash target (hex)")
    p_crack.add_argument("--algo", default="sha256", choices=SUPPORTED_ALGORITHMS)
    p_crack.add_argument("--salt", default="", help="Salt opsional, sama dengan saat hashing")
    p_crack.add_argument("--mode", default="dictionary", choices=["dictionary", "bruteforce"])
    # dictionary mode
    p_crack.add_argument("--wordlist", help="Path ke file wordlist (mode dictionary)")
    p_crack.add_argument("--workers", type=int, default=4, help="Jumlah thread (mode dictionary)")
    # bruteforce mode
    p_crack.add_argument("--charset", default="lower",
                          help=f"Preset: {', '.join(CHARSETS)} atau karakter custom")
    p_crack.add_argument("--min-length", type=int, default=1)
    p_crack.add_argument("--max-length", type=int, default=4)
    p_crack.set_defaults(func=cmd_crack)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
