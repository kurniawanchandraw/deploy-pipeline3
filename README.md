# API OCR & Deteksi Ancaman

API ini berfungsi sebagai endpoint utama untuk menganalisis gambar screenshot. Aplikasi akan melakukan **Optical Character Recognition (OCR)** untuk mengekstrak teks, kemudian menggunakan **AI (Google Gemini)** untuk mengklasifikasikan konten menjadi:

- **Teks biasa** (potensi spam)
- **URL** (potensi phishing)

Hasil klasifikasi dikirim ke API deteksi yang relevan. Ini merupakan bagian dari sistem deteksi ancaman yang lebih besar sebagai jembatan antara input gambar dan layanan analisis backend.

---

## 🧩 Arsitektur & Alur Kerja

Endpoint utama: `/process_screenshot/`

### Alur Kerja:

1. **Menerima Gambar**  
   Klien mengirimkan file gambar (`.png`, `.jpg`, dll) via POST request.

2. **Penyimpanan Sementara**  
   Gambar disimpan sementara di server.

3. **OCR**  
   Menggunakan Tesseract OCR untuk mengekstrak teks dari gambar.

4. **Ekstraksi & Klasifikasi AI** (via Google Gemini):
   - Mengidentifikasi dan mengekstrak semua **URL**
   - Menggabungkan semua **konten teks** yang relevan
   - Mengabaikan email dari kategori URL
   - Mengembalikan hasil dalam format JSON terstruktur

5. **Pemanggilan API Backend**:
   - Teks → dikirim ke **API Deteksi Spam**
   - URL → dikirim ke **API Deteksi Phishing**

6. **Agregasi Hasil**  
   Menggabungkan output OCR, hasil LLM, dan deteksi menjadi satu JSON.

7. **Pembersihan**  
   File gambar sementara dihapus.

---

## ⚙️ Teknologi yang Digunakan

| Komponen | Teknologi |
|---------|-----------|
| Framework | FastAPI |
| OCR Engine | Tesseract OCR |
| AI/LLM | Google Gemini (via `google-generativeai`) |
| Image Processing | Pillow |
| HTTP Requests | requests |
| Deployment | Docker, Railway |

---

## 🛠️ Pengaturan & Instalasi

### 1. Dependensi Sistem
Tesseract OCR dengan bahasa Indonesia dan Inggris:
```bash
apt-get install -y tesseract-ocr tesseract-ocr-eng tesseract-ocr-ind
```

### 2. Dependensi Python

Instal semua library Python dari `requirements.txt`:

```bash
pip install -r requirements.txt
```

### 3. Konfigurasi Environment Variables

| Variable                     | Deskripsi                                       |
| ---------------------------- | ----------------------------------------------- |
| `GOOGLE_API_KEY`             | API Key untuk Google Gemini                     |
| `SPAM_PREDICT_API_URL`       | Endpoint API deteksi spam                       |
| `PHISHING_PREDICT_API_URL`   | Endpoint API deteksi phishing                   |
| `TESSERACT_CMD` *(opsional)* | Path ke executable Tesseract jika tidak di PATH |

---

## 📡 Cara Menggunakan API

### Endpoint Utama: `POST /process_screenshot/`

* **Metode:** POST
* **Body:** `multipart/form-data`
* **Parameter:**

  * `image`: file gambar (`.png`, `.jpg`, `.jpeg`, `.bmp`, `.tiff`)

#### Contoh Request menggunakan `curl`:

```bash
curl -X POST \
  -F "image=@/path/ke/gambar/anda.png" \
  https://nama-proyek-anda.up.railway.app/process_screenshot/
```

#### Contoh Respons Sukses:

```json
{
  "ocr_output_snippet": "MENERIMA RITUAL SEPERTI -Pesugihan uang gaib -Pelet asmra...",
  "llm_extraction": {
    "extracted_urls": [
      {
        "url": "wa.me/082317823334",
        "original_ocr_snippet": "WA=082317823334"
      },
      {
        "url": "http://bit.ly/danapesugihan",
        "original_ocr_snippet": "bit.ly/danapesugihan"
      }
    ],
    "potential_sms_content": "MENERIMA RITUAL SEPERTI -Pesugihan uang gaib -Pelet asmra -Santet Jark jauh,dll di jamin Berhsil WA=082317823334 A/Klik Di",
    "contains_urls": true,
    "contains_text_content": true
  },
  "spam_detection_results": [
    {
      "analysed_text_snippet": "MENERIMA RITUAL SEPERTI -Pesugihan uang gaib -Pelet asmra -Santet Jark jauh,dll di jamin Berhsil WA=082317823334 A/Klik Di",
      "detection_result": {
        "prediction": "SPAM",
        "probability": 0.9998,
        "explanation": "...",
        "source": "..."
      }
    }
  ],
  "phishing_detection_results": [
    {
      "url": "wa.me/082317823334",
      "detection_result": {
        "url": "http://wa.me/082317823334",
        "predicted_type": "Aman",
        "phishing_probability": 0.0012,
        "error": null
      }
    },
    {
      "url": "bit.ly/danapesugihan",
      "detection_result": {
        "url": "http://bit.ly/danapesugihan",
        "predicted_type": "Phishing",
        "phishing_probability": 0.9543,
        "error": null
      }
    }
  ]
}
```

---

### Endpoint Lain: `GET /status`

* **Metode:** GET
* **Tujuan:** Mengecek status API

#### Respons:

```json
{
  "status": "API is running",
  "message": "Welcome to OCR & Threat Detection API!"
}
```
