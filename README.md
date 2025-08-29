# Web Deep Extractor (passive, read-only)

Tool ini mengekstrak data publik dari website, termasuk scanning source (HTML + inline JS + external JS) untuk string yang tampak seperti username/password/token publik.

⚠️ **LEGAL**: Gunakan hanya di situs yang kamu miliki atau yang kamu punya izin tertulis untuk diuji.

## Fitur
- Crawl same-host pages (batas max_pages)
- Parse forms & inputs (method/action/inputs/flags)
- Fetch inline and external JS (same-host by default)
- Scan JS and HTML untuk credential-like literals (var user="...", password:"...", visible "Username: alice")
- Simpan laporan ke `sessions/` (TXT & JSON)

## Instalasi
```bash
git clone https://github.com/oscaroffc/form-analisis.git
```
```bash
cd form-analisis
```
```bash
python3 -m venv venv
```
```bash
source venv/bin/activate
```
```bash
pip install -r requirements.txt
```
### Cara Pakai
```bash
python3 analisis.py --target https://example.com
```
# Ketik YES ketika diminta konfirmasi izin


### Opsi:

--max-pages N : batas halaman yang di-crawl
--no-save : tampilkan JSON ke terminal, tidak menyimpan ke disk
--allow-cross-host-js : juga fetch JS dari domain lain (gunakan hati-hati)

### Output

sessions/<host>_<timestamp>.txt  — human-readable report
sessions/<host>_<timestamp>.json — structured JSON report

### Catatan teknis

Tool ini hanya membaca sumber publik via HTTP(S). Tidak mencoba login, brute-force, atau mengakses file sensitif di server.

Hati-hati: beberapa situs besar bisa memblokir crawling agresif; gunakan --max-pages kecil dan REQUEST_DELAY lebih besar untuk etika.

## 🌐 Platform

| Platform   | Badge | Aturan Kredit |
|------------|-------|---------------|
| 🐙 GitHub   | ![GH](https://img.shields.io/badge/GitHub-181717?style=flat&logo=github&logoColor=white) | `https://github.com/oscaroffc` |
| ▶️ YouTube  | ![YT](https://img.shields.io/badge/YouTube-FF0000?style=flat&logo=youtube&logoColor=white) | `https://youtube.com/@oscar-offc` |
| 🎵 TikTok   | ![TT](https://img.shields.io/badge/TikTok-000000?style=flat&logo=tiktok&logoColor=white) | `no tiktok` |
