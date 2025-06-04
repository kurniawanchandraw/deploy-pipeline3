# main.py

import pytesseract
from PIL import Image
import google.generativeai as genai
import json
import os
import requests
import uuid # Untuk membuat nama file unik sementara
import shutil # Untuk menghapus direktori sementara
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel # Tidak digunakan saat ini, bisa dihapus jika tidak ada rencana

# --- Konfigurasi Logging Awal ---
print("DEBUG: Memulai aplikasi FastAPI...")

# --- Konfigurasi Global & Environment Variables ---
print("DEBUG: Mengambil Environment Variables...")
TESSERACT_CMD_PATH = os.environ.get('TESSERACT_CMD')
if TESSERACT_CMD_PATH:
    print(f"DEBUG: TESSERACT_CMD_PATH ditemukan: {TESSERACT_CMD_PATH}")
    pytesseract.pytesseract.tesseract_cmd = TESSERACT_CMD_PATH
else:
    print("DEBUG: TESSERACT_CMD_PATH tidak diatur, pytesseract akan mencari di PATH sistem.")

GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY')
SPAM_PREDICT_API_URL = os.environ.get('SPAM_PREDICT_API_URL')
# PHISHING_PREDICT_API_URL = os.environ.get('PHISHING_PREDICT_API_URL') # Untuk nanti

print(f"DEBUG: GOOGLE_API_KEY (sebagian): ...{GOOGLE_API_KEY[-6:] if GOOGLE_API_KEY and len(GOOGLE_API_KEY) > 6 else 'TIDAK ADA ATAU TERLALU PENDEK'}")
print(f"DEBUG: SPAM_PREDICT_API_URL: {SPAM_PREDICT_API_URL}")

if not GOOGLE_API_KEY:
    print("ERROR FATAL: Environment variable GOOGLE_API_KEY belum diatur!")
    raise ValueError("Environment variable GOOGLE_API_KEY belum diatur!")

try:
    print("DEBUG: Mengkonfigurasi library genai dengan API key...")
    genai.configure(api_key=GOOGLE_API_KEY)
    print("DEBUG: Konfigurasi genai.configure BERHASIL.")

    # Debug: Cek apakah API key valid dengan mencoba mengambil daftar model
    print("DEBUG: Memvalidasi API key dengan mengambil daftar model Gemini...")
    model_count = 0
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            model_count += 1
    
    if model_count > 0:
        print(f"DEBUG: Validasi API Key BERHASIL. Ditemukan {model_count} model yang mendukung generateContent.")
    else:
        # Ini seharusnya tidak terjadi jika API key valid dan API service aktif
        print("ERROR FATAL: Tidak ada model Gemini yang mendukung generateContent ditemukan. Periksa API key, koneksi, atau status layanan Google.")
        raise ValueError("Tidak ada model yang mendukung generateContent ditemukan. Periksa API key atau koneksi.")

except Exception as e:
    # Menangkap error dari genai.configure() atau genai.list_models()
    print(f"ERROR FATAL saat konfigurasi atau validasi API Key Gemini: {type(e).__name__} - {str(e)}")
    # Detail error akan membantu mengetahui apakah ini 'API_KEY_INVALID' atau masalah lain
    raise ValueError(f"Gagal validasi API Key Gemini saat startup: {str(e)}")
        
# Inisialisasi FastAPI
print("DEBUG: Menginisialisasi aplikasi FastAPI...")
app = FastAPI(title="OCR & Threat Detection API", version="1.0.0")
print("DEBUG: Aplikasi FastAPI berhasil diinisialisasi.")

# Tambahkan ini setelah inisialisasi app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Direktori untuk menyimpan gambar yang diupload sementara
TEMP_IMAGE_DIR = "temp_uploaded_images"
if not os.path.exists(TEMP_IMAGE_DIR):
    print(f"DEBUG: Membuat direktori sementara: {TEMP_IMAGE_DIR}")
    os.makedirs(TEMP_IMAGE_DIR, exist_ok=True)
else:
    print(f"DEBUG: Direktori sementara sudah ada: {TEMP_IMAGE_DIR}")


# --- Fungsi Helper ---

def perform_ocr(image_path: str, lang: str = 'eng+ind') -> str | None:
    print(f"DEBUG OCR: Memulai OCR untuk gambar: {image_path}")
    try:
        img = Image.open(image_path)
        custom_config = r'--oem 3 --psm 6'
        extracted_text = pytesseract.image_to_string(img, lang=lang, config=custom_config)
        print("--- Hasil Teks dari Tesseract ---")
        print(extracted_text)
        print("---------------------------------")
        print(f"DEBUG OCR: OCR berhasil untuk {image_path}.")
        return extracted_text
    except FileNotFoundError:
        print(f"Error OCR: File gambar tidak ditemukan di {image_path}")
        raise HTTPException(status_code=404, detail=f"File gambar tidak ditemukan di server path: {image_path}")
    except pytesseract.TesseractNotFoundError:
        error_msg = "Error OCR: Tesseract tidak ditemukan atau tidak ada di PATH server. Pastikan Tesseract terinstal di environment deployment."
        print(error_msg)
        raise HTTPException(status_code=500, detail=error_msg)
    except Exception as e:
        print(f"Error OCR Lain pada {image_path}: {type(e).__name__} - {str(e)}")
        raise HTTPException(status_code=500, detail=f"Terjadi kesalahan saat OCR: {str(e)}")


def extract_info_with_gemini(text_from_ocr: str,
                             temperature: float = 0.1,
                             top_p: float = 0.95,
                             top_k: int = 40,
                             max_tokens: int = 1024) -> dict | None:
    print(f"DEBUG Gemini: Memulai ekstraksi info dari teks OCR (panjang: {len(text_from_ocr)} karakter).")
    if not text_from_ocr or not text_from_ocr.strip():
        print("Info Gemini: Teks input kosong atau hanya spasi, tidak memanggil API Gemini.")
        return {
            "extracted_urls": [],
            "potential_sms_content": "", # Diubah menjadi string kosong agar konsisten
            "contains_urls": False,
            "contains_text_content": False
        }

    model = genai.GenerativeModel('gemini-1.5-flash') # Pastikan model ini sesuai dengan API key dan projectmu
    
    # Perbaikan pada contoh JSON di dalam prompt
    prompt = f"""
    Anda adalah asisten AI yang sangat ahli dalam menganalisis teks hasil OCR dan mengekstraksi informasi relevan untuk deteksi phishing dan spam.
    Tugas Anda adalah membaca teks berikut yang berasal dari OCR sebuah gambar, lalu:
    1. Identifikasi dan ekstrak SEMUA string yang merupakan URL atau link.
    2. Identifikasi dan ekstrak SEMUA segmen teks yang relevan yang BUKAN merupakan URL (ini bisa jadi konten SMS).

    Perhatikan hal-hal berikut untuk EKSTRAKSI URL:
    - URL bisa dalam berbagai format: dimulai dengan http://, https://, www., atau bahkan hanya domain.tld (misalnya, example.com).
    - Kenali juga skema URL non-HTTP seperti wa.me/, ftp://, mailto:, dll.
    - Teks OCR mungkin mengandung kesalahan. Cobalah untuk mengoreksi kesalahan umum pada URL (misalnya, "http:ll" menjadi "http://", "example. com" menjadi "example.com", "g00gle.com" menjadi "google.com").
    - Untuk setiap URL yang diekstrak, sertakan "url" yang dikoreksi dan "original_ocr_snippet" (potongan teks OCR asli tempat URL itu ditemukan, jika memungkinkan dan relevan).

    Perhatikan hal-hal berikut untuk EKSTRAKSI KONTEN TEKS (NON-URL):
    - Fokus pada teks yang terlihat seperti pesan, promosi, instruksi, atau informasi yang biasanya dikirim melalui SMS atau platform pesan.
    - Abaikan teks-teks yang sangat pendek, tidak bermakna, atau noise dari antarmuka pengguna (misalnya, "Text Message", "Today 5:03 PM", nama operator), kecuali jika itu bagian tak terpisahkan dari pesan utama.
    - Hasil "potential_sms_content" harus berupa SATU STRING TUNGGAL yang berisi gabungan semua teks relevan yang ditemukan. Jika ada beberapa paragraf atau baris teks yang relevan, gabungkan menjadi satu string dengan newline karakter jika sesuai untuk menjaga keterbacaan.

    Teks dari OCR:
    ---
    {text_from_ocr}
    ---

    Berikan output HANYA dalam format JSON berikut.
    - Jika tidak ada URL yang ditemukan, "extracted_urls" harus berupa list kosong dan "contains_urls" harus false.
    - Jika tidak ada konten teks relevan (non-URL) yang ditemukan, "potential_sms_content" harus berupa string kosong dan "contains_text_content" harus false.

    {{
      "extracted_urls": [
        {{
          "url": "url_yang_benar_dan_sudah_dikoreksi_1",
          "original_ocr_snippet": "potongan_teks_ocr_asli_opsional_1"
        }}
      ],
      "potential_sms_content": "satu_string_gabungan_semua_teks_sms_relevan_hasil_gemini",
      "contains_urls": false,
      "contains_text_content": false
    }}
    Pastikan output adalah JSON yang valid dan tidak ada teks penjelasan lain di luar blok JSON.
    """
    generation_config = genai.types.GenerationConfig(
        temperature=temperature, top_p=top_p, top_k=top_k, max_output_tokens=max_tokens
    )
    try:
        print("DEBUG Gemini: Mengirim request ke model.generate_content...")
        response = model.generate_content(prompt, generation_config=generation_config)
        print("DEBUG Gemini: Respons diterima dari model.")
        
        cleaned_response_text = response.text.strip()
        if cleaned_response_text.startswith("```json"):
            cleaned_response_text = cleaned_response_text[7:]
        if cleaned_response_text.endswith("```"):
            cleaned_response_text = cleaned_response_text[:-3]
        cleaned_response_text = cleaned_response_text.strip()
        
        # print(f"DEBUG Gemini: Cleaned response text for JSON parsing:\n{cleaned_response_text}")
        parsed_output = json.loads(cleaned_response_text)
        print("DEBUG Gemini: Parsing JSON respons BERHASIL.")

        # Pastikan potential_sms_content adalah string
        if isinstance(parsed_output.get("potential_sms_content"), list):
            print("DEBUG Gemini: Mengubah potential_sms_content dari list menjadi string.")
            parsed_output["potential_sms_content"] = " ".join(parsed_output["potential_sms_content"])

        return parsed_output
    except json.JSONDecodeError as e:
        print(f"Error Gemini: Gagal parsing JSON - {e}")
        print(f"Raw Response Text dari Gemini yang gagal di-parse:\n{response.text if 'response' in locals() and hasattr(response, 'text') else 'N/A atau response tidak punya .text'}")
        raise HTTPException(status_code=500, detail="Gagal memproses respons dari LLM (JSON Decode Error).")
    except Exception as e:
        error_detail = f"Error Gemini Lain: {type(e).__name__} - {str(e)}"
        if 'response' in locals() and hasattr(response, 'prompt_feedback'):
             error_detail += f" | Prompt Feedback: {response.prompt_feedback}"
        print(error_detail) # Ini akan mencetak error 'API key not valid' jika itu masalahnya
        raise HTTPException(status_code=500, detail=f"Terjadi kesalahan saat berkomunikasi dengan LLM: {str(e)}")


def detect_spam_via_api(text_to_check: str) -> dict | None:
    print(f"DEBUG API Spam: Mengirim teks (awal: '{text_to_check[:50]}...') ke {SPAM_PREDICT_API_URL}")
    if not SPAM_PREDICT_API_URL:
        print("Error API Spam: SPAM_PREDICT_API_URL belum dikonfigurasi.")
        return {"error": "URL API Spam tidak dikonfigurasi."} # Kembalikan dict agar konsisten
    try:
        payload = {"text": text_to_check}
        response = requests.post(SPAM_PREDICT_API_URL, json=payload, timeout=20)
        print(f"DEBUG API Spam: Status respons dari API Spam: {response.status_code}")
        response.raise_for_status()
        result = response.json()
        print("DEBUG API Spam: Respons JSON diterima dan diparsing.")
        return result
    except requests.exceptions.Timeout:
        print(f"Error API Spam: Request timeout ke {SPAM_PREDICT_API_URL}")
        return {"error": "API Spam timeout."}
    except requests.exceptions.RequestException as e:
        print(f"Error API Spam: Tidak bisa terhubung atau request gagal - {e}")
        return {"error": f"Gagal menghubungi API Spam: {str(e)}"}
    except json.JSONDecodeError:
        print(f"Error API Spam: Respons bukan JSON valid.")
        print(f"Raw Response dari API Spam: {response.text if 'response' in locals() else 'N/A'}")
        return {"error": "Respons API Spam tidak valid."}

# --- Endpoint FastAPI ---
@app.get("/status", summary="Cek status API", tags=["Utility"])
async def get_status():
    """Endpoint sederhana untuk mengecek apakah API berjalan."""
    print("DEBUG: Endpoint /status diakses.")
    return {"status": "API is running", "message": "Welcome to OCR & Threat Detection API!"}

@app.post("/process_screenshot/", summary="Proses Screenshot untuk Deteksi Ancaman", tags=["Processing"])
async def process_screenshot(image: UploadFile = File(..., description="File gambar screenshot (PNG, JPG, JPEG, BMP, TIFF)")):
    """
    Endpoint untuk memproses screenshot:
    1. Menerima file gambar.
    2. Melakukan OCR.
    3. Mengirim teks OCR ke Gemini untuk ekstraksi URL dan teks SMS.
    4. Mengirim teks SMS ke API deteksi spam.
    5. (Future) Mengirim URL ke API deteksi phishing.
    """
    print(f"DEBUG Endpoint: Menerima request ke /process_screenshot untuk file: {image.filename}")
    temp_image_path = None
    try:
        file_extension = os.path.splitext(image.filename)[1]
        if not file_extension.lower() in ['.png', '.jpg', '.jpeg', '.bmp', '.tiff']:
            print(f"ERROR Endpoint: Format file tidak didukung: {image.filename}")
            raise HTTPException(status_code=400, detail="Format file tidak didukung. Gunakan PNG, JPG, JPEG, BMP, atau TIFF.")

        temp_image_filename = f"{uuid.uuid4()}{file_extension}"
        temp_image_path = os.path.join(TEMP_IMAGE_DIR, temp_image_filename)
        print(f"DEBUG Endpoint: Menyimpan gambar sementara ke: {temp_image_path}")

        with open(temp_image_path, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)
        print(f"DEBUG Endpoint: Gambar sementara berhasil disimpan.")

        # 1. Lakukan OCR
        ocr_text = perform_ocr(temp_image_path)
        # perform_ocr sudah raise HTTPException jika ada error fatal, 
        # jadi jika sampai sini dan ocr_text is None, itu kasus yang tidak terduga atau error minor.
        # Untuk keamanan, kita tetap anggap teks kosong jika None.
        if ocr_text is None: ocr_text = "" 

        # 2. Ekstrak informasi menggunakan Gemini LLM
        gemini_extraction_results = extract_info_with_gemini(ocr_text)
        # extract_info_with_gemini sudah raise HTTPException jika ada error fatal
        if gemini_extraction_results is None:
             # Ini seharusnya tidak tercapai jika error handling di extract_info_with_gemini benar
            raise HTTPException(status_code=500, detail="Gagal mendapatkan hasil ekstraksi dari LLM (hasil None tak terduga).")

        # 3. Proses Deteksi Spam
        spam_detection_outputs = []
        potential_sms_content = gemini_extraction_results.get("potential_sms_content", "")
        
        if gemini_extraction_results.get("contains_text_content") and potential_sms_content and potential_sms_content.strip():
            print(f"\n[INFO] Konten teks (SMS) terdeteksi. Mengirim ke API Deteksi Spam.")
            spam_result = detect_spam_via_api(potential_sms_content)
            # spam_result akan berisi dict dengan 'error' jika gagal, atau hasil prediksi jika berhasil
            spam_detection_outputs.append({
                "analysed_text_snippet": potential_sms_content[:200] + "..." if len(potential_sms_content) > 200 else potential_sms_content,
                "detection_result": spam_result
            })
        else:
            print("\n[INFO] Tidak ada konten teks (SMS) relevan yang diekstrak oleh Gemini untuk deteksi spam.")

        # 4. Proses Deteksi Phishing (Placeholder)
        phishing_detection_outputs = []
        extracted_urls_objects = gemini_extraction_results.get("extracted_urls", [])
        if gemini_extraction_results.get("contains_urls") and extracted_urls_objects:
            print("\n[INFO] URL terdeteksi. (Integrasi deteksi phishing akan menyusul)")
            for url_obj in extracted_urls_objects:
                url_to_check = url_obj.get("url")
                if url_to_check:
                    print(f"  -> URL Ditemukan: {url_to_check}")
                    phishing_detection_outputs.append({
                        "url": url_to_check,
                        "detection_result": {"status": "Phishing detection not yet implemented."}
                    })
        else:
            print("\n[INFO] Tidak ada URL yang diekstrak oleh Gemini.")

        final_response = {
            "ocr_output_snippet": ocr_text[:500] + "..." if len(ocr_text) > 500 else ocr_text, # Kirim snippet saja
            "llm_extraction": gemini_extraction_results,
            "spam_detection_results": spam_detection_outputs,
            "phishing_detection_results": phishing_detection_outputs
        }
        print("DEBUG Endpoint: Mengirim respons akhir.")
        return JSONResponse(content=final_response)

    except HTTPException as http_exc:
        print(f"DEBUG Endpoint: HTTPException ditangkap: {http_exc.status_code} - {http_exc.detail}")
        raise http_exc # Re-raise agar FastAPI menanganinya
    except Exception as e:
        print(f"ERROR FATAL Tak Terduga di endpoint /process_screenshot: {type(e).__name__} - {str(e)}")
        # Cetak traceback untuk error tak terduga
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Terjadi kesalahan internal server yang tidak terduga: {str(e)}")
    finally:
        if temp_image_path and os.path.exists(temp_image_path):
            try:
                os.remove(temp_image_path)
                print(f"DEBUG Endpoint: File sementara {temp_image_path} dihapus.")
            except Exception as e_remove:
                print(f"ERROR Endpoint: Gagal menghapus file sementara {temp_image_path}: {e_remove}")

# Jalankan dengan Uvicorn (untuk development lokal):
# uvicorn main:app --reload
# print("DEBUG: Skrip main.py selesai dieksekusi (level global). Aplikasi FastAPI seharusnya berjalan jika dipanggil via uvicorn.")
