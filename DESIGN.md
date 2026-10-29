# DESIGN.md — WhoisDNS Web Tools

Spesifikasi sistem desain, arsitektur visual, token, dan tata letak responsif untuk WhoisDNS Web Tools (Domain & Deep DNS Inspector).
Dirancang dengan prinsip utilitas rekayasa jaringan (network telemetry utility): hierarki data padat, nol dekorasi semu (anti-slop), aksesibilitas WCAG AA, dan adaptasi layout mobile-first yang kokoh.

---

## 1. Filosofi & Karakter Visual

### Karakter: Engineering Telemetry Utility
- **Bukan Fiksi / Cyberpunk Cosplay**: Menghilangkan efek neon berlebih, bayangan pendar (glow) artifisial, dan hiasan visual tanpa fungsi teknis.
- **Inspirasi Sistem**: Standar visual konsol telemetri modern (Datadog, Cloudflare Dashboard, Linear, Vercel Dashboard) — fungsional, bersih, kontras tinggi, dan berorientasi data.
- **Prioritas Informasi**: Kecepatan pemindaian mata (scannability), pembedaan tipe data (nama domain, IP, record flag, TTL) secara instan, serta kenyamanan mata pada sesi analisis jaringan yang panjang.

---

## 2. Arsitektur Desain Token (3-Layer Architecture)

Sistem token menggunakan hierarki 3 lapis: Primitive (nilai mentah), Semantic (tujuan kontekstual), dan Component (spesifik elemen).

### Layer 1: Primitive Tokens
```css
:root {
  /* Palet Netral (Slate Base) */
  --primitive-slate-950: #0B0F17; /* Background Kanvas Utama */
  --primitive-slate-900: #111827; /* Surface Level 1 (Kartu / Container) */
  --primitive-slate-850: #162032; /* Surface Level 2 (Sub-card / Input) */
  --primitive-slate-800: #1E293B; /* Border Default */
  --primitive-slate-700: #334155; /* Border Interaktif / Divider */
  --primitive-slate-600: #475569; /* Ikon & Elemen Non-fokus */
  --primitive-slate-400: #94A3B8; /* Teks Sekunder / Metadata */
  --primitive-slate-200: #E2E8F0; /* Teks Primer High-Contrast */
  --primitive-white:     #FFFFFF; /* Teks Nilai Utama / Data Kritis */

  /* Palet Aksen Fungsional */
  --primitive-sky-500:   #0284C7; /* Brand Primer / Aksi Aktif */
  --primitive-sky-400:   #38BDF8; /* Highlight Interaktif / Link */
  --primitive-sky-950:   #082F49; /* Tint Background Aksen */

  /* Status Semantik Jaringan */
  --primitive-emerald-500: #10B981; /* Lolos / Valid / Aman */
  --primitive-emerald-950: #064E3B; /* Background Status Lolos */
  --primitive-amber-500:   #F59E0B; /* Peringatan / Kadaluwarsa Dekat */
  --primitive-amber-950:   #451A03; /* Background Status Peringatan */
  --primitive-rose-500:    #F43F5E; /* Eror / Resolusi Gagal / Bahaya */
  --primitive-rose-950:    #4C0519; /* Background Status Eror */

  /* Radius (Geometri Terukur) */
  --radius-xs: 4px;
  --radius-sm: 6px;
  --radius-md: 8px;
  --radius-lg: 12px;
  --radius-full: 9999px;

  /* Spasi Skala 4px/8px */
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-6: 24px;
  --space-8: 32px;
  --space-12: 48px;
}
```

### Layer 2: Semantic Tokens
```css
:root {
  /* Background & Surface */
  --color-bg-base:           var(--primitive-slate-950);
  --color-bg-surface:        var(--primitive-slate-900);
  --color-bg-surface-raised: var(--primitive-slate-850);
  --color-bg-overlay:        rgba(11, 15, 23, 0.85);

  /* Border */
  --color-border-subtle:     var(--primitive-slate-800);
  --color-border-strong:     var(--primitive-slate-700);
  --color-border-interactive:var(--primitive-sky-500);

  /* Teks (Kontras Minimum WCAG AA 4.5:1) */
  --color-text-main:         var(--primitive-slate-200); /* Kontras 12.8:1 */
  --color-text-bright:       var(--primitive-white);     /* Kontras 15.4:1 */
  --color-text-muted:        var(--primitive-slate-400); /* Kontras 5.2:1 */
  --color-text-dim:          var(--primitive-slate-600);

  /* Feedback Semantik */
  --color-status-pass:       var(--primitive-emerald-500);
  --color-status-pass-bg:    rgba(16, 185, 129, 0.12);
  --color-status-warn:       var(--primitive-amber-500);
  --color-status-warn-bg:    rgba(245, 158, 11, 0.12);
  --color-status-fail:       var(--primitive-rose-500);
  --color-status-fail-bg:    rgba(244, 63, 94, 0.12);

  /* Fokus & Navigasi Keyboard */
  --color-focus-ring:        var(--primitive-sky-400);
  --focus-outline:           2px solid var(--color-focus-ring);
  --focus-offset:            2px;
}
```

### Layer 3: Component Tokens
- **Omnibox Search**:
  - `height`: 48px (mobile), 52px (desktop).
  - `background`: `var(--color-bg-surface-raised)`.
  - `border`: `1px solid var(--color-border-subtle)` -> transisi `1px solid var(--color-border-interactive)` pada `:focus-within`.
  - `box-shadow`: tanpa glow berlebih, hanya bayangan elevasi fisik `0 2px 8px rgba(0,0,0,0.4)`.
- **KPI Metrics Card**:
  - `padding`: 14px (mobile) hingga 18px (desktop).
  - `background`: `var(--color-bg-surface)`.
  - `border`: `1px solid var(--color-border-subtle)`.
  - `label-color`: `var(--color-text-muted)`, uppercase tracking 0.05em, font size 11px.
  - `value-color`: `var(--color-text-bright)`, font mono tabular-nums, font size `clamp(1.1rem, 2vw, 1.35rem)`.
- **DNS Records Table**:
  - `header-bg`: `var(--primitive-slate-850)`.
  - `row-hover`: `rgba(255, 255, 255, 0.02)`.
  - `border-bottom`: `1px solid var(--color-border-subtle)`.
  - `type-badge`: padding 2px 8px, font size 11px, weight 700, radius 4px. Warna konsisten per kategori rekor (A/AAAA = Biru, MX/TXT = Jingga/Ungu, NS/SOA = Hijau).
- **WHOIS Raw Console**:
  - `background`: `#070A0F`.
  - `border`: `1px solid var(--color-border-subtle)`.
  - `font`: `JetBrains Mono`, 13px, line-height 1.6.
  - **Larangan**: Tidak menggunakan hiasan tombol merah/kuning/hijau khas macOS palsu jika bukan jendela aplikasi desktop native. Sediakan header fungsional berisi metadata koneksi TCP socket, toggle word-wrap, dan tombol salin.

---

## 3. Sistem Tipografi & Skala Fluida

Kombinasi dua keluarga font untuk kejelasan fungsional:
1. **UI Sans (`Inter`, system-ui)**: Digunakan untuk antarmuka, heading, label formulir, navigasi, dan pesan panduan.
2. **Data Monospace (`JetBrains Mono`, `Fira Code`)**: Wajib untuk seluruh entitas teknis (nama domain, IP, record values, TTL, kode status EPP, raw output, dan waktu latensi).

### Skala Tipografi Fluida (Menggunakan `clamp()`)
| Peran Tipografi | Nilai Responsif `clamp()` | Bobot | Line Height | Keterangan |
| :--- | :--- | :--- | :--- | :--- |
| **Hero Heading** | `clamp(1.5rem, 4vw, 2.25rem)` (24px - 36px) | 700 | 1.2 | Judul alat utama |
| **Section Title** | `clamp(1.2rem, 2.5vw, 1.5rem)` (19px - 24px) | 600 | 1.3 | Judul tab / segmen data |
| **Domain Target** | `clamp(1.1rem, 3vw, 1.6rem)` (17px - 26px) | 600 (Mono) | 1.3 | Indikator target audit aktif |
| **KPI Value** | `clamp(1.15rem, 2vw, 1.35rem)` (18px - 22px) | 700 (Mono) | 1.2 | Nilai metrik (Umur, Tanggal, Rekor) |
| **Body UI** | `14px` (`0.875rem`) | 400 / 500 | 1.5 | Teks deskripsi dan instruksi |
| **Table & Code Data** | `13px` (`0.8125rem`) (Mono) | 400 / 500 | 1.55 | Data rekor DNS, alamat IP, serial |
| **Metadata & Badges**| `11px` (`0.6875rem`) | 600 / 700 | 1.4 | Label status, header kolom, TTL |

### Aturan Khusus Mobile Safari / iOS
- Seluruh elemen `<input>` dan `<select>` pada layar sentuh wajib memiliki ukuran font minimum `16px` (atau `font-size: max(16px, 1rem)`) guna mencegah browser iOS melakukan auto-zoom paksa saat fokus.

---

## 4. Tata Letak Responsif & Mobile Reflow Engine

Arsitektur tata letak menganut prinsip continuous reflow (mulai dari 320px tanpa horizontal scroll leak hingga layar desktop lebar 1440px).

### 1. Viewport & Satuan Dimensi
- Gunakan `min-height: 100dvh` (Dynamic Viewport Height) untuk menghindari lonjakan layout akibat kemunculan/penyembunyian URL bar pada browser mobile (Chrome Android, Safari iOS).
- Batas maksimal kontainer utama: `max-width: 1280px` terpusat dengan padding samping dinamis:
  - Layar `< 640px`: `padding: 0 16px`
  - Layar `640px - 1023px`: `padding: 0 24px`
  - Layar `>= 1024px`: `padding: 0 32px`

### 2. Tiga Tingkat Reflow Konten (3-Tier Content Reflow)

#### A. Mobile Portrait (< 640px)
- **Omnibox Form**: Input dan tombol pencarian bertumpuk vertikal atau tombol masuk ke dalam input sebagai icon-button dengan ukuran tap target minimal `44x44px`.
- **KPI Metrics**: Reflow otomatis menjadi grid 2 kolom x 2 baris (bukan 4 kolom terjepit horizontal).
- **Tab Navigasi**:
  - Disusun horizontal dengan overflow terisolasi (`overflow-x: auto; white-space: nowrap`).
  - Mengaktifkan `-webkit-overflow-scrolling: touch` dan `scrollbar-width: none`.
  - Dilengkapi bayangan pudar (gradient mask) di sisi kanan sebagai tanda visual bahwa tab dapat digeser.
  - Setiap tab item memiliki tinggi minimum `44px` dan padding horizontal `16px`.
- **Tabel Rekor DNS**:
  - Dibungkus dalam kontainer `.table-scroll-container` dengan `overflow-x: auto`.
  - Kolom tipe rekor (`A`, `MX`, dll.) bersifat sticky di sisi kiri saat tabel digeser ke kanan.
  - Alternatif tampilan: opsi tampilan kartu (Card View) untuk layar di bawah 480px agar setiap rekor dapat dibaca tanpa geser horizontal.
- **Nilai Teks Panjang (IP, Hash, DKIM)**:
  - Wajib menerapkan `word-break: break-all` atau pemotongan aman dengan tombol salin cepat di sampingnya.

#### B. Tablet & Layar Menengah (640px - 1023px)
- **KPI Metrics**: 4 kolom seimbang dalam 1 baris atau 2 kolom lebar.
- **Overview Card Grid**: 2 kolom modular dengan pemisahan proporsional antara modul Security Audit dan Registrar Info.
- **DNS Records Table**: Kolom tabel ditampilkan penuh (Type, Host, Target/Value, TTL, Action Copy).

#### C. Desktop Lebar (≥ 1024px)
- **Dashboard Modular**: Layout grid terstruktur 12 kolom untuk metrik, ringkasan cepat, dan detail teknis.
- **Global Propagation Grid**: Grid 4 kolom x 2 baris menampilkan hasil 8 resolver dunia (Google, Cloudflare, Quad9, OpenDNS, AdGuard, DNS.SB, Comodo, Level3) lengkap dengan latensi milidetik dan status kesesuaian IP.

### 3. Pencegahan Kebocoran Horizontal (Zero Horizontal Overflow Policy)
- Tidak ada elemen yang boleh memiliki lebar tetap (fixed width) yang melebihi `100vw`.
- Kontainer blok raw WHOIS dan kode DNS menggunakan:
  ```css
  .raw-output-block {
    max-width: 100%;
    overflow-x: auto;
    white-space: pre;
    font-family: var(--font-mono);
  }
  ```
- Seluruh ikon interaktif dan tombol aksi memiliki bounding box minimum `44px x 44px` untuk kepatuhan tap target jari manusia.

---

## 5. Spesifikasi Komponen & Status Visual Lengkap

Setiap komponen interaktif wajib mendefinisikan seluruh status visual (complete states) agar antarmuka komunikatif dan tidak membingungkan pengguna:

### 1. Status Komponen (State Matrix)
| Komponen | Default | Hover | Active / Focus-Visible | Disabled | Loading / Empty |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Search Input** | Border `slate-800`, bg `slate-850` | Border `slate-700` | Border `sky-500`, outline 2px sky-400 | Opacity 0.6, cursor not-allowed | Indikator loader spinner non-blocking di sisi kanan input |
| **Tombol Aksi** | Bg `sky-600`, teks putih | Bg `sky-500` | Bg `sky-700`, ring offset 2px | Opacity 0.5, pointer-events none | Teks berubah menjadi status proses + spinner inline |
| **Tab Item** | Teks `slate-400`, garis bawah transparan | Teks `slate-200`, bg `rgba(255,255,255,0.03)` | Teks `white`, border-bottom 2px `sky-400` | Teks `slate-600` | Animasi shimmer skeleton pada konten tab |
| **Baris Tabel** | Border bottom `slate-800` | Bg `rgba(255,255,255,0.02)` | Bg `rgba(2,132,199,0.08)` saat dipilih | - | Skeleton table row 4 baris berkedip halus |
| **Tombol Salin** | Ikon monokrom `slate-400`, tap box 44px | Teks/ikon `slate-200` | Feedback tooltip "Tersalin!" warna hijau 1.5 detik | - | - |

### 2. Desain Penanganan Eror & Keadaan Kosong (Empty / Error States)
- **Keadaan Kosong Awal (Initial State)**: Tampilkan panduan ringkas, contoh domain populer yang dapat diklik langsung (`google.com`, `cloudflare.com`, `wikipedia.org`), serta instruksi pintasan keyboard (tekan `/` untuk fokus ke omnibox).
- **Keadaan Eror Jaringan / Domain Tidak Ditemukan**:
  - Dilarang hanya menampilkan pesan mentah: `NXDOMAIN` atau `Socket error`.
  - Berikan kartu peringatan terstruktur:
    1. **Apa yang Terjadi**: `Domain tidak terdaftar atau gagal diresolusi.`
    2. **Penyebab Potensial**: `Salah ketik pada TLD, rekor DNS baru saja diubah (propagasi belum selesai), atau server WHOIS menolak koneksi port 43.`
    3. **Tindakan Pemulihan**: Tombol "Coba Lagi", opsi "Cek via Cloudflare DoH Client-side", dan tautan ke riwayat query.

---

## 6. Aksesibilitas (WCAG 2.1 AA) & Performa

- **Kontras Warna**: Seluruh pasangan warna teks terhadap background diuji memenuhi rasio minimal:
  - Teks reguler (< 18px): minimal 4.5:1.
  - Teks tebal / data teknis besar: minimal 3:1.
  - Nilai data kritis putih murni di atas surface `slate-900` mencapai rasio 15:1+.
- **Navigasi Keyboard**:
  - Tombol `Tab` berpindah logis dari Omnibox -> Filter Rekor -> Tab Bar -> Aksi Salin -> Footer.
  - `:focus-visible` menggunakan outline kontras tinggi (2px solid `sky-400` dengan offset 2px), tidak boleh dihilangkan tanpa pengganti yang terlihat jelas.
- **Preferensi Gerak (Reduced Motion)**:
  ```css
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
      animation-duration: 0.01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: 0.01ms !important;
      scroll-behavior: auto !important;
    }
  }
  ```

---

## 7. Larangan AI-Slop (Anti-Slop Directives)

Berikut daftar larangan ketat dalam implementasi antarmuka WhoisDNS Web Tools:
1. **Dilarang Menggunakan Emoji Sebagai Ikon UI**: Seluruh icon wajib menggunakan format SVG inline yang bersih, presisi, dan dapat diubah warnanya via `currentColor` (standar Lucide Icons / Heroicons).
2. **Dilarang Efek Glow / Pendar Neon Artifisial**: Hapus bayangan seperti `box-shadow: 0 0 25px rgba(0, 229, 255, 0.8)`. Gunakan kontras permukaan bertingkat (elevation via background color) dan border 1px yang terukur.
3. **Dilarang Kosmetik Terminal Palsu**: Hapus hiasan 3 lingkaran merah-kuning-hijau macOS palsu pada card atau tabel. Antarmuka ini adalah tool web profesional, bukan screenshot demo fiksi.
4. **Dilarang Copy Teks / Nilai Placeholder Palsu**: Dilarang memuat teks `Lorem Ipsum`, `Coming Soon`, atau data simulasi dummy tanpa indikator yang jelas. Seluruh metrik wajib merefleksikan data jaringan aktual.
5. **Dilarang Teks Token Campuran / Bahasa Campur Aduk**: Hilangkan sisa-sisa translasi generik AI (seperti istilah bahasa Spanyol atau fragmen instruksi mesin). Seluruh dokumentasi dan kode menggunakan terminologi rekayasa web terstandar.
6. **Dilarang Mengabaikan Tap Target Mobile**: Setiap kontrol yang dapat diklik atau disentuh pengguna wajib memiliki ruang sentuh minimum 44x44px.
