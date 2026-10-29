# WhoisDNS Web Tools — Deep Domain & DNS Inspector

Web Tools modern berkinerja tinggi untuk pengecekan detail Domain WHOIS, pemindaian menyeluruh semua tipe DNS Record (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `CAA`, `SRV`), audit keamanan email & DNS (`SPF`, `DMARC`, `DNSSEC`), serta visualisasi propagasi global Anycast resolver secara real-time.

---

## ⚡ Fitur Utama

1. **Authoritative Socket WHOIS (Port 43 TCP):**
   - Menghubungi server registri resmi via TCP socket port 43 dengan penanganan referral IANA (`whois.iana.org` &rarr; Registry TLD &rarr; Registrar).
   - Mendukung semua TLD global: gTLD (`.com`, `.org`, `.net`, `.io`, `.xyz`, dll.) hingga ccTLD lokal (`.id`, `.co.id`, `.ac.id`, `.uk`, `.de`, `.sg`, dll.).
   - Decoding status domain ICANN EPP (misal: `clientTransferProhibited`, `serverHold`, `redemptionPeriod`).
   - Perhitungan otomatis umur domain (Domain Age) dan countdown hari aktif hingga kedaluwarsa.
   - Dilengkapi fallback otomatis ke protokol RDAP (`rdap.org`).

2. **Deep DNS Records Inspector:**
   - Menyelesaikan 9 tipe rekor DNS standar sekaligus:
     - **A** (IPv4 Address beserta nilai TTL)
     - **AAAA** (IPv6 Dual-Stack Support)
     - **CNAME** (Canonical Aliases)
     - **MX** (Mail Exchange berurutan berdasarkan nilai prioritas)
     - **TXT** (Parsing otomatis untuk SPF, Google/Microsoft/Apple site verification, dsb.)
     - **NS** (Authoritative Nameservers)
     - **SOA** (Primary NS, Hostmaster email, Serial number, Refresh, Retry, Expire, Min TTL)
     - **CAA** (Certification Authority Authorization untuk penerbitan sertifikat SSL)
     - **SRV** (Pengecekan protokol layanan seperti Autodiscover, SIP, XMPP)
   - Filter instan per tipe rekor dan pencarian teks langsung di dalam tabel rekor.

3. **DNS & Email Security Health Audit:**
   - **SPF Validation:** Evaluasi mekanisme `-all` (strict) vs `~all` (softfail).
   - **DMARC Compliance:** Pemeriksaan TXT `_dmarc.<domain>` untuk mengetahui kebijakan (`reject`, `quarantine`, `none`) dan persentase kepatuhan.
   - **DNSSEC Verification:** Pengecekan delegasi kunci DS kriptografis.
   - **Nameserver Redundancy:** Memastikan domain memiliki minimal 2 NS terdistribusi.
   - **CAA Policy Check:** Mengetahui apakah penerbitan SSL dibatasi pada CA tertentu.

4. **Global Anycast DNS Propagation Checker:**
   - Menguji resolusi domain secara simultan ke 8 Anycast Public DNS resolver dunia:
     - Cloudflare (1.1.1.1)
     - Google Public DNS (8.8.8.8)
     - Quad9 Security (9.9.9.9)
     - OpenDNS Cisco (208.67.222.222)
     - AdGuard DNS (94.140.14.14)
     - Comodo Secure DNS (8.26.56.26)
     - Lumen / Level3 (4.2.2.2)
     - DNS.SB Privacy (185.222.222.222)
   - Mengukur latensi respon (ms), konsistensi nilai IP, dan persentase propagasi global.

5. **IP Geolocation & Reverse DNS (PTR):**
   - Klik pada setiap alamat IP untuk melihat Reverse DNS PTR, ISP, Autonomous System (ASN), Organisasi, Kota, dan Negara.

6. **Ekspor & Alat Salin:**
   - Salin rekor tunggal, salin seluruh rekor DNS, salin raw WHOIS, atau ekspor laporan lengkap ke format file `.json`.
   - URL shareable (`?q=domain.com`) untuk membagikan hasil pengecekan langsung kepada rekan kerja.

---

## 🚀 Cara Menjalankan Proyek

### Prasyarat
- **Node.js**: versi 18.x atau yang lebih baru (disarankan v20+ atau v24).
- **NPM**: bawaan Node.js.

### 1. Instalasi Dependensi
```bash
npm install
```

### 2. Jalankan Server
Untuk mode produksi:
```bash
npm start
```

Untuk mode pengembangan (dengan auto-reload):
```bash
npm run dev
```

Buka peramban (browser) di:
```
http://localhost:3000
```

---

## 📡 Dokumentasi Endpoint REST API

| Method | Endpoint | Deskripsi | Parameter Query |
|---|---|---|---|
| `GET` | `/api/lookup` | Pemindaian terpadu (WHOIS + Seluruh DNS + Health Audit + GeoIP) | `domain` atau `q` |
| `GET` | `/api/whois` | Data registrasi WHOIS terstruktur & raw stream | `domain` atau `q` |
| `GET` | `/api/dns` | Resolusi DNS spesifik atau seluruh tipe | `domain` & `type` (`ALL`, `A`, `MX`, dll.) |
| `GET` | `/api/propagation` | Pengecekan propagasi 8 Anycast resolver | `domain` & `type` (`A`, `AAAA`, `MX`, dll.) |
| `GET` | `/api/ip` | Reverse DNS PTR & GeoIP data untuk sebuah IP | `ip` |
| `GET` | `/api/health` | Status engine dan uptime server | - |

Contoh pemanggilan API menggunakan cURL atau fetch:
```bash
# Unified lookup
curl "http://localhost:3000/api/lookup?domain=github.com"

# DNS TXT records
curl "http://localhost:3000/api/dns?domain=google.com&type=TXT"

# Global propagation
curl "http://localhost:3000/api/propagation?domain=kompas.id&type=A"
```

---

## 🎨 Desain & UI/UX
Spesifikasi palet warna, tipografi, dan prinsip desain didokumentasikan secara rinci di [DESIGN.md](file:///c:/Users/Administrator/Documents/PROJECT-GITHUB/DNS/DESIGN.md).
