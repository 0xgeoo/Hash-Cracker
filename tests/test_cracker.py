"""
Unit tests sederhana (pakai unittest, stdlib only — tidak perlu pytest).
Jalankan dengan: python -m unittest discover tests
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hash_cracker.hash_utils import compute_hash, identify_hash, looks_like_hash
from hash_cracker.cracker import dictionary_attack, brute_force_attack

WORDLIST = str(Path(__file__).resolve().parent.parent / "wordlists" / "common_passwords.txt")


class TestHashUtils(unittest.TestCase):
    def test_compute_hash_md5(self):
        self.assertEqual(
            compute_hash("password", "md5"),
            "5f4dcc3b5aa765d61d8327deb882cf99",
        )

    def test_compute_hash_sha256(self):
        self.assertEqual(
            compute_hash("hello", "sha256"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )

    def test_compute_hash_with_salt_changes_output(self):
        plain = compute_hash("password", "sha256")
        salted = compute_hash("password", "sha256", salt="pepper")
        self.assertNotEqual(plain, salted)

    def test_identify_hash_md5_length(self):
        h = compute_hash("test", "md5")
        self.assertIn("md5", identify_hash(h))

    def test_identify_hash_sha256_length(self):
        h = compute_hash("test", "sha256")
        self.assertIn("sha256", identify_hash(h))

    def test_looks_like_hash_rejects_non_hex(self):
        self.assertFalse(looks_like_hash("not-a-hash!!"))

    def test_invalid_algorithm_raises(self):
        with self.assertRaises(ValueError):
            compute_hash("x", "md6")


class TestDictionaryAttack(unittest.TestCase):
    def test_finds_known_password(self):
        target = compute_hash("password1", "sha256")
        result = dictionary_attack(target, "sha256", WORDLIST, workers=2)
        self.assertTrue(result.found)
        self.assertEqual(result.plaintext, "password1")

    def test_returns_not_found_for_unknown_password(self):
        target = compute_hash("not-in-the-list-xyz", "sha256")
        result = dictionary_attack(target, "sha256", WORDLIST, workers=2)
        self.assertFalse(result.found)


class TestBruteForceAttack(unittest.TestCase):
    def test_finds_short_password(self):
        target = compute_hash("ab1", "md5")
        result = brute_force_attack(
            target, "md5",
            charset="abcdefghijklmnopqrstuvwxyz0123456789",
            min_length=1, max_length=3,
        )
        self.assertTrue(result.found)
        self.assertEqual(result.plaintext, "ab1")


if __name__ == "__main__":
    unittest.main()
