# 🕵️‍♂️ Rafza18 Recon Tool

**Rafza18 Recon Tool** adalah sebuah script Python untuk melakukan *reconnaissance* (pengumpulan informasi) pada sebuah domain.
Fitur-fitur ini memanfaatkan teknik passive & active untuk menganalisis target dengan berbagai metode.

✨ **Logo & credits: Rafza18**

---

## 📋 Fitur

✅ Whois lookup
✅ Shodan host info (butuh API key)
✅ DNS Zone Transfer test
✅ Subdomain enumeration dari file `.js`
✅ CORS misconfiguration check
✅ WAF detection
✅ CDN detection
✅ CMS detection
✅ Open ports check
✅ TLS certificate enumeration (Certspotter)
✅ GitHub dorking

---

## 🔧 Persiapan

### 📁 File yang Diperlukan

Pastikan di direktori yang sama ada file:

* `cakancoli.py` — script utama
* `common.txt` — wordlist untuk enumerasi (sudah disediakan)
* `proxies.txt` — daftar proxy (sudah disediakan)
* `user_agents.txt` — daftar User-Agent (kamu isi sendiri, 1 User-Agent per baris)

---

## 📦 Install Dependensi

### Cara 1: install satu per satu

```bash
pip install requests beautifulsoup4 dnspython aiohttp
```

### Cara 2: dengan requirements.txt

Buat file `requirements.txt` berisi:

```
requests
beautifulsoup4
dnspython
aiohttp
```

lalu jalankan:

```bash
pip install -r requirements.txt
```

---

## 🚀 Cara Menjalankan

### Opsi 1 — Jalankan & Gunakan di Python Shell

```bash
python cakancoli.py
```

Script hanya akan menampilkan logo & memuat data.
Untuk menjalankan salah satu modulnya, buka Python shell:

Contoh:

```python
from cakancoli import siWhoisPasif
siWhoisPasif().jalan("example.com")
```

Atau modul lain:

```python
from cakancoli import siSubdomainHunter
siSubdomainHunter().jalan("example.com")
```

---

### Opsi 2 — (Opsional) Tambahkan Fungsi Utama

Jika ingin script langsung menanyakan domain & menjalankan semua modul otomatis, kamu bisa tambahkan fungsi `main()` di `cakancoli.py`.

---

## 📑 Konfigurasi Shodan

Jika ingin memakai fitur Shodan, ubah baris berikut pada `cakancoli.py`:

```python
url = f"https://api.shodan.io/shodan/host/{ip}?key=SHODAN_API_KEY"
```

Ganti `SHODAN_API_KEY` dengan API key Shodan milikmu.

---

## 👨‍💻 Dibuat Oleh

**Rafza18**
🕵️‍♂️ Jangan berpikir aneh melihat logonya, ini mahakarya by Rafza18. 😉

---
