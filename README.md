# WhoisDNS Web Tools — Deep Domain & DNS Inspector

Web Tools modern berkinerja tinggi untuk pengecekan detail Domain WHOIS, pemindaian menyeluruh tipe DNS Record, audit keamanan email & DNS (SPF, DMARC, DKIM, DNSSEC), serta visualisasi propagasi global Anycast resolver secara real-time.

---

## Fitur Utama

1. **Authoritative Socket WHOIS (Port 43 TCP):**
   - Menghubungi server registri resmi via TCP socket port 43 dengan penanganan referral IANA (`whois.iana.org` &rarr; Registry TLD &rarr; Registrar).
   - Mendukung semua TLD global: gTLD (`.com`, `.org`, `.net`, `.io`, `.xyz`, dll.) hingga ccTLD lokal (`.id`, `.co.id`, `.ac.id`, `.uk`, `.de`, `.sg`, `.au`, dll.) melalui **Public Suffix List** (`tldts`), bukan daftar hardcoded.
   - **Selalu query domain registrable (eTLD+1)**: input `mail.google.com` akan memeriksa `google.com`, sehingga subdomain tidak pernah salah dilaporkan sebagai "Available".
   - Decoding status domain ICANN EPP (misal: `clientTransferProhibited`, `serverHold`, `redemptionPeriod`).
   - Perhitungan otomatis umur domain (Domain Age) dan countdown hari hingga kedaluwarsa.
   - Fallback otomatis ke protokol RDAP (`rdap.org`) bila socket port 43 gagal.

2. **Deep DNS Records Inspector (via DNS-over-HTTPS):**
   - Menyelesaikan **15 tipe rekor** sekaligus, lengkap dengan **TTL untuk semua tipe**:
     - **A**, **AAAA**, **CNAME**, **MX**, **TXT**, **NS**, **SOA**, **CAA**, **SRV**
     - **HTTPS** / **SVCB** (service binding, HTTP/3 & ECH hints)
     - **DS**, **DNSKEY** (delegasi DNSSEC)
     - **TLSA** (DANE), **NAPTR**
   - Parsing otomatis TXT: SPF, DMARC, DKIM, BIMI, verifikasi Google/Microsoft/Apple/Facebook.
   - Filter instan per tipe rekor + pencarian teks langsung di dalam tabel.
   - CNAME chain detection (redirect/alias berantai sampai 6 hop).

3. **DNS & Email Security Health Audit (10 checks):**
   - **SPF Validation:** evaluasi qualifier `-all` / `~all` / `+all` dan hitungan DNS lookup (batas RFC 7208 = 10).
   - **DMARC Compliance:** kebijakan `reject` / `quarantine` / `none`, `pct`, `rua`, `ruf`.
   - **DKIM Discovery:** probing selector umum (`default`, `google`, `selector1`, `selector2`, `k1`, `mail`, `dkim`).
   - **DNSSEC Verification:** DS + DNSKEY via DoH serta flag `AD` (authenticated data).
   - **Nameserver Redundancy:** minimal 2 NS terdistribusi.
   - **CAA Policy Check:** pembatasan CA penerbit sertifikat SSL.
   - **HTTPS/SVCB Presence:** kesiapan HTTP/3 dan Encrypted Client Hello.

4. **Global Anycast DNS Propagation Checker:**
   - Menguji resolusi domain secara simultan ke 8 Anycast Public DNS resolver dunia (Cloudflare, Google, Quad9, OpenDNS, AdGuard, Comodo, Lumen, DNS.SB).
   - Mendukung tipe A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, SRV, HTTPS.
   - Mengukur latensi respon (ms), konsistensi nilai, dan persentase propagasi global.
   - Resolver di-`cancel()` saat timeout sehingga tidak ada handle menggantung.

5. **IP Geolocation & Reverse DNS (PTR):**
   - Klik pada setiap alamat IP untuk melihat Reverse DNS PTR, ISP, Autonomous System (ASN), Organisasi, Kota, dan Negara.
   - Mendukung IPv4 dan IPv6.

6. **Ekspor & Alat Salin:**
   - Salin rekor tunggal, salin seluruh rekor DNS, salin raw WHOIS, atau ekspor laporan lengkap ke `.json`.
   - URL shareable (`?q=domain.com`).

7. **Produksi-ready:**
   - Cache in-memory ber-TTL (WHOIS 1 jam, DNS 5 menit mengikuti TTL record, IP 30 menit) &rarr; lookup berulang turun dari ~3s ke ~15ms.
   - Rate limiting per-IP 120 request/menit dengan header `X-RateLimit-*` dan `Retry-After`.
   - `helmet` security headers + CSP, `compression` (gzip/brotli), `cors` terkonfigurasi.
   - Validasi input ketat: proteksi DNS/WHOIS injection (CRLF), punycode IDN, deteksi IPv4/IPv6.
   - Error handling konsisten: `400` untuk input invalid, `404` JSON untuk endpoint tak dikenal, `500` tanpa membocorkan stack trace.

---

## Cara Menjalankan Proyek

### Prasyarat
- **Node.js**: versi **18.17+** (disarankan v20+ atau v24) — wajib karena memakai `fetch` global.

### 1. Instalasi Dependensi
```bash
npm install
```

### 2. Jalankan Server
Untuk mode produksi:
```bash
npm start
```

Untuk mode pengembangan (auto-reload):
```bash
npm run dev
```

Buka browser di: `http://localhost:3000`

### 3. Test & Lint
```bash
npm test    # 26 test: unit + API integration
npm run lint
```

---

## Dokumentasi Endpoint REST API

| Method | Endpoint | Deskripsi | Parameter Query |
|---|---|---|---|
| `GET` | `/api/lookup` | Pemindaian terpadu (WHOIS + seluruh DNS + email auth + health audit + GeoIP + CNAME chain) | `domain` atau `q` |
| `GET` | `/api/whois` | Data registrasi WHOIS terstruktur & raw stream | `domain` atau `q` |
| `GET` | `/api/dns` | Resolusi DNS spesifik atau seluruh tipe | `domain` & `type` (`ALL`, `A`, `HTTPS`, `DNSKEY`, dll.) |
| `GET` | `/api/propagation` | Pengecekan propagasi 8 Anycast resolver | `domain` & `type` |
| `GET` | `/api/ip` | Reverse DNS PTR & GeoIP untuk IPv4/IPv6 | `ip` |
| `GET` | `/api/health` | Status engine, uptime, dan statistik cache | - |

Contoh pemanggilan:
```bash
# Unified lookup
curl "http://localhost:3000/api/lookup?domain=github.com"

# Subdomain (otomatis di-resolve ke domain registrable)
curl "http://localhost:3000/api/lookup?domain=mail.google.com"

# DNS HTTPS/SVCB records
curl "http://localhost:3000/api/dns?domain=cloudflare.com&type=HTTPS"

# Global propagation
curl "http://localhost:3000/api/propagation?domain=kompas.id&type=A"
```

### Contoh Response Error
```json
{ "error": "Enter a full domain name including its TLD (example.com).", "input": "foo" }
```
```json
{ "error": "Unknown API endpoint: GET /api/nope", "endpoints": ["/api/health", "..."] }
```

---

## Struktur Proyek

```
DNS/
├── server.js              # Express app: routing, middleware, error handling
├── api/index.js           # Entry point Vercel serverless
├── lib/
│   ├── domain.js          # Validasi input, eTLD+1, punycode, deteksi IP
│   ├── whois.js           # Socket WHOIS port 43 + referral + fallback RDAP
│   ├── doh.js             # Klien DNS-over-HTTPS + normalisasi record
│   ├── dns.js             # Resolusi 15 tipe record, email auth, DNSSEC, health
│   ├── propagation.js     # Pengecekan 8 resolver global
│   ├── ip.js              # Reverse DNS PTR + GeoIP/ASN
│   ├── cache.js           # TTL cache berbatas kapasitas
│   └── ratelimit.js       # Fixed-window rate limiter
├── public/                # Frontend (HTML/CSS/JS, tanpa build step)
└── test/                  # Unit + API integration test (node:test)
```

---

## Catatan Deployment

- **Node/VPS/Docker (disarankan):** semua fitur aktif, termasuk WHOIS socket port 43.
- **Vercel / platform serverless:** banyak platform memblokir outbound TCP port 43. WHOIS akan otomatis fallback ke RDAP (hasil tetap terisi, raw text berupa JSON RDAP). DNS, propagasi, dan IP lookup tetap berfungsi normal.

## Desain & UI/UX
Spesifikasi palet warna, tipografi, dan prinsip desain didokumentasikan di [DESIGN.md](DESIGN.md).
