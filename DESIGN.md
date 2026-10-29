# DESIGN.md - WhoisDNS Web Tools (Domain & Deep DNS Inspector)

## 1. Visual Theme & Atmosphere
Desain mengusung konsep **High-Tech Cyberpunk Terminal & Telemetry Dashboard** yang mengutamakan kecepatan membaca data teknis, kontras tinggi (OLED-friendly), dan kejelasan visual untuk Network Engineer, Sysadmin, dan DevOps. 
Antarmuka terinspirasi dari telemetry dashboard modern (Power BI / Grafana / Linear) dengan kartu data modular, penanda status warna-warni yang tegas, dan tipografi proporsional.

---

## 2. Color Palette & Design Tokens

### Primitive & Semantic Colors
- **Background Primario:** `#0C1017` / `#121212` (Dark Mode murni, minim emisi cahaya, efisiensi visual tinggi).
- **Superficie de Tarjetas (Card Surface):** `#141B27` / `#182234` (Elevasi visual lembut dengan kontras terukur).
- **Borde de Tarjetas:** `1px solid #24344D` (Hover state dengan highlight cyan `rgba(0, 229, 255, 0.35)`).
- **Acento Primario (Data & Action):** `#00E5FF` (Neon Cyan) untuk tombol primer, nilai KPI utama, indikator fokus, dan highlight query.
- **Acento Secundario (Status Positif):** `#32D74B` / `#22C55E` (Emerald Green) untuk status domain aktif, validasi DNSSEC bertanda tangan, dan hasil lolos uji kesehatan (pass audit).
- **Acento de Alerta (Warning/Error):** `#FF453A` (Vibrant Coral Red) untuk domain kedaluwarsa (expired), kegagalan resolusi, atau kerentanan kritis.
- **Acento Precaución (Warning):** `#F59E0B` (Amber/Gold) untuk domain yang mendekati masa habis (expiring soon) atau rekor keamanan yang belum optimal (DMARC missing).
- **Texto Principal:** `#FFFFFF` / `#F8FAFC` (Kontras 14:1+ WCAG AAA).
- **Texto Secundario:** `#94A3B8` / `#98989D` (Label metadata, deskripsi pembantu).
- **Texto Sutil:** `#64748B` (Placeholder, border subtle).

---

## 3. Typography System
- **UI Fonts & Body Copy:** `Inter`, -apple-system, sans-serif (Font size base 16px, body 14px, heading 24px - 36px).
- **Data, Records & Network Addresses:** `JetBrains Mono` / `Fira Code` (Font monospace untuk IP addresses, TTL, serial numbers, SOA records, hash, dan raw stream port 43 socket).
- **Visual Hierarchy:**
  - Hero Display Title: 36px / 2.25rem (Weight: 800)
  - Domain Target: 28px / 1.85rem (Font Mono, Weight: 700)
  - KPI Metrics Value: 22px / 1.35rem (Font Mono, Weight: 700)
  - Card Header: 17px / 1.05rem (Weight: 700)
  - Table Body: 14px / 0.875rem (Font Mono, Weight: 400/500)

---

## 4. Layout & Architecture Principles
- **Grid Structure:** 12-column responsive layout dengan kelipatan spasi 8px (8px, 16px, 24px, 32px).
- **Header & Omnibox:** Search box terpusat yang menerima format domain fleksibel (`google.com`, `https://kompas.id`, `1.1.1.1`), otomatis melakukan pembersihan protokol dan path.
- **4 Key Metrics (Top KPI Row):**
  1. **Registrar & IANA ID:** Identitas pengelola resmi domain.
  2. **Domain Age:** Umur domain dalam tahun dan jumlah hari sejak didaftarkan.
  3. **Expiration & Countdown:** Tanggal kedaluwarsa beserta sisa hari aktif.
  4. **DNS Records Count & Latency:** Total rekor ditemukan dan waktu resolusi (ms).
- **Tab Navigation Bar:**
  - `Overview`: Ringkasan checklist audit DNS & keamanan (SPF, DMARC, DNSSEC, NS, CAA), Authoritative NS, Mail Exchange (MX), dan Geo IP Host.
  - `DNS Records`: Tabel komprehensif 9 tipe rekor (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `CAA`, `SRV`) dengan filter cepat dan pencarian teks seketika.
  - `WHOIS Details`: Metadata registrar terstruktur, tanggal registrasi, kontak registrant, dan decoding kode status ICANN EPP (misal: `clientTransferProhibited`).
  - `Global Propagation`: Uji coba langsung secara simultan ke 8 Anycast Resolver dunia (Cloudflare, Google, Quad9, OpenDNS, AdGuard, Comodo, Level3, DNS.SB) dengan indikator persentase ketersebaran dan latensi ms.
  - `Raw WHOIS`: Tampilan terminal stream langsung port 43 TCP socket dengan toggle word wrap dan tombol salin.

---

## 5. Security & Network Protocols Handled
- **Authoritative Port 43 Socket:** Menghubungi port 43 langsung via TCP socket dengan discovery otomatis referral IANA TLD (`whois.iana.org` -> Registry TLD -> Registrar WHOIS).
- **DNS Record Types:**
  - `A` (IPv4)
  - `AAAA` (IPv6)
  - `CNAME` (Canonical alias)
  - `MX` (Mail server priority & exchange)
  - `TXT` (SPF, Google Verification, Microsoft Verification, Apple Verification, dll.)
  - `NS` (Authoritative Nameservers)
  - `SOA` (Start of Authority: Primary NS, Hostmaster/Admin, Serial, Refresh, Retry, Expire, Min TTL)
  - `CAA` (Certification Authority Authorization)
  - `SRV` (Service records: Autodiscover, SIP, XMPP)
- **Email & DNS Security Audit:**
  - Evaluasi SPF (`v=spf1`) sintaks dan mekanisme (`-all` vs `~all`)
  - Evaluasi DMARC (`_dmarc.domain`) policy (`reject`, `quarantine`, `none`)
  - Uji DS Delegation DNSSEC
  - Redundansi Nameserver (minimal 2 NS terdistribusi)

---

## 6. Do's and Don'ts
- ✅ **Do:** Gunakan font monospace (`JetBrains Mono`) untuk seluruh data teknis (IP, TTL, Domain, Rekor DNS, Raw WHOIS).
- ✅ **Do:** Sediakan aksi salin instan (Copy) dan ekspor laporan (JSON/CSV) untuk mempermudah audit teknis.
- ✅ **Do:** Gunakan SVG icons yang bersih (Lucide/Heroicons style) dan dilarang keras menggunakan emoji sebagai icon.
- ✅ **Do:** Sediakan mode fallback client-side DoH jika backend sedang offline.
- ❌ **Don't:** Menggunakan warna pastel atau background putih terang yang merusak kontras data teknis.
- ❌ **Don't:** Menampilkan pesan error mentah tanpa instruksi perbaikan yang jelas kepada pengguna.