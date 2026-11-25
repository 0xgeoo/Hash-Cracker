# Hash Cracker (Python)

Project edukasi cybersecurity tingkat *beginner*: tool CLI untuk meng-crack hash
satu-arah (MD5, SHA-1, SHA-2 family) lewat **dictionary attack** dan
**brute-force attack**. Dibuat terinspirasi dari struktur project
[Cybersecurity-Projects — Hash Cracker](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/hash-cracker),
ditulis ulang dalam Python (stdlib saja, tanpa dependency eksternal).

## ⚠️ Etika & Legalitas

Gunakan tool ini **hanya** untuk:
- Memahami cara kerja hashing dan mengapa password lemah mudah ditebak.
- Hash milik Anda sendiri, lab, CTF, atau sistem dengan izin eksplisit.

Meng-crack kredensial milik orang lain tanpa izin adalah **ilegal** di hampir
semua yurisdiksi (termasuk Indonesia, lihat UU ITE). Tool ini tidak dimaksudkan
dan tidak boleh dipakai untuk menyerang sistem pihak ketiga.

## Konsep yang Dipelajari

| Konsep | Penjelasan singkat |
|---|---|
| Hash satu-arah | Fungsi yang mudah dihitung maju, tapi (secara praktis) tidak bisa dibalik |
| Dictionary attack | Coba daftar kata umum/bocoran sebagai kandidat password |
| Brute-force attack | Coba semua kombinasi karakter secara sistematis |
| Salting | Menambah data acak ke password sebelum hashing untuk menggagalkan rainbow table |
| Mengapa MD5/SHA1 "cepat" itu buruk untuk password | Algoritma cepat = penyerang bisa coba jutaan/detik; bandingkan dengan bcrypt/argon2 yang sengaja lambat |

## Struktur Project

```
hash-cracker/
├── main.py                       # CLI entry point
├── hash_cracker/
│   ├── __init__.py
│   ├── hash_utils.py             # compute_hash(), identify_hash()
│   ├── wordlist.py               # loader wordlist (generator, hemat memori)
│   └── cracker.py                # dictionary_attack(), brute_force_attack()
├── wordlists/
│   └── common_passwords.txt      # contoh wordlist kecil (30 password umum)
├── tests/
│   └── test_cracker.py           # unit test (stdlib unittest)
└── README.md
```

## Instalasi

Tidak ada dependency eksternal — hanya butuh Python 3.9+.

```bash
cd hash-cracker
python3 -m unittest discover tests   # jalankan test (opsional, untuk verifikasi)
```

## Pemakaian

### 1. Hitung hash dari sebuah teks (buat target uji coba sendiri)

```bash
python3 main.py hash --text "password123" --algo sha256
```

### 2. Identifikasi kemungkinan algoritma dari sebuah hash

```bash
python3 main.py identify --hash 0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e
```

### 3. Dictionary attack

```bash
python3 main.py crack \
  --hash <hash_target> \
  --algo sha256 \
  --wordlist wordlists/common_passwords.txt \
  --workers 4
```

Ganti `wordlists/common_passwords.txt` dengan wordlist yang lebih besar (mis.
`rockyou.txt`) untuk cakupan lebih luas — loader memakai generator sehingga
aman untuk file berukuran jutaan baris.

### 4. Brute-force attack

```bash
python3 main.py crack \
  --hash <hash_target> \
  --algo md5 \
  --mode bruteforce \
  --charset alnum \
  --min-length 1 \
  --max-length 5
```

Preset `--charset`: `lower`, `upper`, `letters`, `digits`, `alnum`, `all`
(atau masukkan set karakter custom sendiri, mis. `--charset abc123`).

> Ruang pencarian brute-force tumbuh secara eksponensial
> (`len(charset) ** panjang`), jadi `max-length` besar dengan charset besar
> bisa berjalan sangat lama — ini bagian dari pelajarannya: makin panjang &
> acak password, makin aman.

### 5. Hash dengan salt

```bash
python3 main.py hash --text "password123" --algo sha256 --salt "s4lt!"
python3 main.py crack --hash <hash> --algo sha256 --salt "s4lt!" --wordlist wordlists/common_passwords.txt
```

## Pengembangan Lebih Lanjut (Ide Latihan)

- Tambahkan dukungan rule-based mutation (mis. `password` → `P@ssw0rd!`).
- Tambahkan progress bar yang lebih baik (mis. pakai `tqdm`).
- Tambahkan dukungan GPU/multiprocessing untuk brute-force yang lebih berat.
- Bandingkan kecepatan crack MD5/SHA256 vs bcrypt/argon2 untuk melihat
  langsung mengapa algoritma "lambat" lebih aman untuk password.
- Tambahkan mode HMAC-aware atau format hash gabungan (mis. `salt$hash`).

## Lisensi

Kode ini bebas dipakai untuk belajar. Gunakan secara bertanggung jawab.
