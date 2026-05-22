# ReconLens AI Copilot: Strategic Improvements Roadmap

Dokumen ini mencatat daftar ide, perbaikan, dan rencana peningkatan jangka panjang untuk asisten **ReconLens AI Copilot** agar menjadi asisten keamanan tingkat tinggi (military-grade) yang sepenuhnya kontekstual dan tangguh.

---

## 🚀 1. UI/UX & Responsive Interaction

### 🟢 Real-Time Streaming & Typing Effects
- **Tujuan**: Menghilangkan persepsi latensi ketika model lokal (seperti Ollama/LM Studio) sedang memproses respon yang panjang.
- **Implementasi**: Gunakan **Server-Sent Events (SSE)** via FastAPI untuk mengalirkan potongan teks (chunks) dari AI secara langsung ke UI obrolan secara real-time.
- **Visual**: Tambahkan efek kursor mengetik berkedip (pulsing cursor caret) di akhir teks yang sedang mengalir.

### 🟢 Multi-Agent Thinking Process (Blinking States)
- **Tujuan**: Ketika asisten sedang memutuskan tindakan atau mengekstrak data dari target, tunjukkan proses berpikirnya secara visual.
- **Visual**: Tambahkan status penunjuk seperti:
  - `🔍 Scanning target subdomains list...`
  - `🧠 Reasoning about next pentest phase...`
  - `📝 Formulating custom CLI command syntax...`

### 🟢 Rich Interactive Markdown Blocks
- **Tujuan**: Menampilkan perintah CLI, daftar URL, dan kode exploit secara bersih dengan fitur salin instan.
- **Implementasi**: Integrasikan pustaka parser markdown (seperti `marked.js` atau `Prism.js`) di frontend untuk mewarnai sintaksis kode (syntax highlighting) dan menambahkan tombol **"Copy Code"** di pojok kanan atas blok kode.

---

## 🧠 2. AI Reasoning & Target Awareness (Context Enrichment)

### 🔵 Active Target Files Context Ingestion (RESOLVED & IMPLEMENTED)
- **Tujuan**: Asisten harus bisa menjawab pertanyaan spesifik tentang data target yang sudah ditemukan (misal: *"apakah ada URL yang mengandung kata 'employer'?"* atau *"subdomain mana saja yang memiliki status HTTP 200?"*).
- **Implementasi**:
  - **Selesai**: Diimplementasikan penangkap heuristik cepat dan pencari string instan (grep-equivalent) di dalam `_act_analyze` di [ai_jobs.py](file:///Users/prasetia/Documents/hacking/antigravity/hackerone/zooplus/ReconLens/app/services/ai_jobs.py). Sistem sekarang menyisir `urls.txt` and `subdomains.txt` secara realtime dan mengembalikan daftar kecocokan langsung ke chat!

### 🔵 Instant Math Calculation Interceptor (RESOLVED & IMPLEMENTED)
- **Tujuan**: Asisten langsung menyelesaikan perhitungan matematis dasar (misal: 5x5 atau 123 + 456) secara lokal tanpa latency LLM.
- **Implementasi**:
  - **Selesai**: Ditambahkan modul kalkulator instan berbasis ekspresi reguler di bagian paling atas [ai_rulegen.py](file:///Users/prasetia/Documents/hacking/antigravity/hackerone/zooplus/ReconLens/app/services/ai_rulegen.py) untuk menyajikan respon chat secepat kilat dengan 0ms LLM latency.

### 🔵 Target Script Storage & Execution Pipeline (RESOLVED & IMPLEMENTED)
- **Tujuan**: AI membuat script (.py/.sh) kustom untuk pengguna, menyimpannya di direktori khusus target, dan mengeksekusinya secara aman dalam sandbox terisolasi.
- **Implementasi**:
  - **Selesai**: Ditambahkan tool `save_script` dan `execute_script` di [ai_jobs.py](file:///Users/prasetia/Documents/hacking/antigravity/hackerone/zooplus/ReconLens/app/services/ai_jobs.py). Script disimpan secara aman di `outputs/<scope>/scripts/`. Ditambahkan pula interseptor heuristik cepat di [ai_rulegen.py](file:///Users/prasetia/Documents/hacking/antigravity/hackerone/zooplus/ReconLens/app/services/ai_rulegen.py) untuk langsung mendeteksi instruksi jalankan script seperti `"jalankan script parser.py"`.

### 🟢 Automated Vulnerability Heuristics (Sec-Agent Mode)
- **Tujuan**: AI merekomendasikan target eksploitasi potensial secara otomatis berdasarkan pola URL yang ditemukan.
- **Implementasi**:
  - Deteksi URL sensitif seperti `.git`, `.env`, `wp-admin`, `wp-config.php`, `config.json`, endpoint API (`/api/v1/`), dll.
  - Berikan tanda centang oranye **"⚠️ Potential Leak Found"** langsung di dalam panel obrolan AI dengan ringkasan penjelasan kerentanannya.

---

## ⚙️ 3. Settings, Backend & Model Orchestration

### 🟢 Auto-Target Host Injection in System Prompt
- **Tujuan**: Memastikan LLM selalu mengingat domain target yang sedang aktif (scope) saat ini tanpa harus berulang kali diberitahu oleh user di setiap chat.
- **Implementasi**: Secara dinamis sisipkan variabel target aktif (misal: `[Current Target: jobsdb.com]`) ke dalam system prompt utama pada setiap panggilan API LLM di `app/services/ai_rulegen.py`.

### 🟢 Hybrid Model Routing (Local vs Cloud Failover)
- **Tujuan**: Memastikan asisten tetap berkinerja tinggi bahkan ketika salah satu provider offline.
- **Implementasi**: Jika koneksi ke Ollama lokal terputus atau mengalami timeout, sistem secara otomatis akan beralih (failover) ke cloud OpenAI/Gemini/Anthropic dengan memberikan notifikasi kecil di UI: *"⚠️ Local LLM offline. Switched to cloud API safely."*

### 🟢 Persistent Context Compression (Memory Summary)
- **Tujuan**: Menghemat token memori ketika percakapan sudah sangat panjang tanpa kehilangan poin diskusi awal.
- **Implementasi**: Ketika jumlah pesan melebihi batas `ctx_size`, buat ringkasan obrolan (chat summaries) menggunakan model AI dan gunakan ringkasan tersebut sebagai jangkar konteks awal menggantikan pesan-pesan lama yang dibuang.
