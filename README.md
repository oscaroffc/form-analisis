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


# 📜 Lisensi Attribution (BY)

![License](https://img.shields.io/badge/License-Attribution%20(BY)-blue?style=for-the-badge)
![Year](https://img.shields.io/badge/Year-2025-green?style=for-the-badge)
![Author](https://img.shields.io/badge/Author-Nama%20Kamu-orange?style=for-the-badge)

Repositori ini dilindungi dengan lisensi **Attribution (BY)**.  
Artinya: bebas dipakai, dimodifikasi, atau dibagikan **selama menyertakan kredit/sumber**.

---

## 🌐 Platform

| Platform   | Badge | Aturan Kredit |
|------------|-------|---------------|
| 💬 WhatsApp | ![WA](https://img.shields.io/badge/WhatsApp-25D366?style=flat&logo=whatsapp&logoColor=white) | Gunakan dengan menyebut sumber WhatsApp: `@nomor_kamu` |
| 🐙 GitHub   | ![GH](https://img.shields.io/badge/GitHub-181717?style=flat&logo=github&logoColor=white) | Kode ini boleh digunakan dengan menyebut sumber GitHub: `@username_kamu` |
| ▶️ YouTube  | ![YT](https://img.shields.io/badge/YouTube-FF0000?style=flat&logo=youtube&logoColor=white) | Video ini boleh digunakan dengan menyebut sumber Channel: `Nama Channel` |
| 🎵 TikTok   | ![TT](https://img.shields.io/badge/TikTok-000000?style=flat&logo=tiktok&logoColor=white) | Konten ini boleh digunakan dengan menyebut sumber TikTok: `@username_kamu` |

---

## 📅 Informasi
- **Author**: Nama Kamu / Organisasi  
- **Tahun**: 2025  
- **Lisensi**: Attribution (BY)  

---

✍️ *“Bebas dipakai dan dibagikan asal mencantumkan kredit sesuai platform.”*
