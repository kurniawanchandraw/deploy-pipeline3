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
from pydantic import BaseModel # Untuk request body jika diperlukan nanti

# --- Konfigurasi Global & Environment Variables ---
# PENTING: Path Tesseract ini mungkin tidak diperlukan atau berbeda di Railway
# Jika Tesseract terinstal via Dockerfile dan ada di PATH sistem, pytesseract biasanya menemukannya.
# Jika masih bermasalah di Railway, Anda mungkin perlu mengaturnya via env var atau investigasi path di container.
TESSERACT_CMD_PATH = os.environ.get('TESSERACT_CMD')
if TESSERACT_CMD_PATH:
    pytesseract.pytesseract.tesseract_cmd = TESSERACT_CMD_PATH

GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY')
SPAM_PREDICT_API_URL = os.environ.get('SPAM_PREDICT_API_URL') # Default jika tidak diset
# PHISHING_PREDICT_API_URL = os.environ.get('PHISHING_PREDICT_API_URL') # Untuk nanti

if not GOOGLE_API_KEY:
    raise ValueError("Environment variable GOOGLE_API_KEY belum diatur!")
genai.configure(api_key=GOOGLE_API_KEY)

# Inisialisasi FastAPI
app = FastAPI(title="OCR & Threat Detection API", version="1.0.0")

# Direktori untuk menyimpan gambar yang diupload sementara
TEMP_IMAGE_DIR = "temp_uploaded_images"
os.makedirs(TEMP_IMAGE_DIR, exist_ok=True)


# --- Fungsi Helper dari Skrip Sebelumnya (dimodifikasi sedikit jika perlu) ---

def perform_ocr(image_path: str, lang: str = 'eng+ind') -> str | None:
    try:
        img = Image.open(image_path)
        custom_config = r'--oem 3 --psm 6'
        extracted_text = pytesseract.image_to_string(img, lang=lang, config=custom_config)
        print("--- Hasil Teks dari Tesseract ---") # Untuk logging di server
        print(extracted_text)
        print("---------------------------------")
        return extracted_text
    except FileNotFoundError:
        print(f"Error OCR: File gambar tidak ditemukan di {image_path}")
        raise HTTPException(status_code=404, detail=f"File gambar tidak ditemukan di server path: {image_path}")
    except pytesseract.TesseractNotFoundError:
        error_msg = "Error OCR: Tesseract tidak ditemukan atau tidak ada di PATH server. Pastikan Tesseract terinstal di environment deployment."
        print(error_msg)
        # Di production, error Tesseract tidak boleh terjadi jika Dockerfile benar.
        raise HTTPException(status_code=500, detail=error_msg)
    except Exception as e:
        print(f"Error OCR Lain: {e}")
        raise HTTPException(status_code=500, detail=f"Terjadi kesalahan saat OCR: {str(e)}")


def extract_info_with_gemini(text_from_ocr: str,
                             temperature: float = 0.1,
                             top_p: float = 0.95,
                             top_k: int = 40,
                             max_tokens: int = 1024) -> dict | None:
    if not text_from_ocr or not text_from_ocr.strip():
        print("Info Gemini: Teks input kosong atau hanya spasi, tidak memanggil API Gemini.")
        # Kembalikan struktur JSON default yang menandakan tidak ada konten
        return {
            "extracted_urls": [],
            "potential_sms_content": [],
            "contains_urls": False,
            "contains_text_content": False
        }

    model = genai.GenerativeModel('gemini-1.5-flash')
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
      "potential_sms_content": "satu_string_gabungan_semua_teks_sms_relevan",
      "contains_urls": false,
      "contains_text_content": false
    }}
    Pastikan output adalah JSON yang valid dan tidak ada teks penjelasan lain di luar blok JSON.
    """
    generation_config = genai.types.GenerationConfig(
        temperature=temperature, top_p=top_p, top_k=top_k, max_output_tokens=max_tokens
    )
    try:
        response = model.generate_content(prompt, generation_config=generation_config)
        cleaned_response_text = response.text.strip()
        if cleaned_response_text.startswith("```json"):
            cleaned_response_text = cleaned_response_text[7:]
        if cleaned_response_text.endswith("```"):
            cleaned_response_text = cleaned_response_text[:-3]
        cleaned_response_text = cleaned_response_text.strip()
        
        # print(f"DEBUG: Cleaned response text for JSON parsing:\n{cleaned_response_text}")
        parsed_output = json.loads(cleaned_response_text)
        # Pastikan potential_sms_content adalah string, bukan list (sesuai modifikasi prompt)
        if isinstance(parsed_output.get("potential_sms_content"), list):
            parsed_output["potential_sms_content"] = " ".join(parsed_output["potential_sms_content"])

        return parsed_output
    except json.JSONDecodeError as e:
        print(f"Error Gemini: Gagal parsing JSON - {e}")
        print(f"Raw Response Text dari Gemini:\n{response.text if 'response' in locals() else 'N/A'}")
        raise HTTPException(status_code=500, detail="Gagal memproses respons dari LLM (JSON Decode Error).")
    except Exception as e:
        error_detail = f"Error Gemini Lain: {e}"
        if 'response' in locals() and hasattr(response, 'prompt_feedback'):
             error_detail += f" | Prompt Feedback: {response.prompt_feedback}"
        print(error_detail)
        raise HTTPException(status_code=500, detail=f"Terjadi kesalahan saat berkomunikasi dengan LLM: {str(e)}")


def detect_spam_via_api(text_to_check: str) -> dict | None:
    if not SPAM_PREDICT_API_URL:
        print("Error: SPAM_PREDICT_API_URL belum dikonfigurasi.")
        return {"error": "URL API Spam tidak dikonfigurasi."}
    try:
        payload = {"text": text_to_check}
        response = requests.post(SPAM_PREDICT_API_URL, json=payload, timeout=20) # Timeout lebih lama untuk API eksternal
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        print(f"Error API Spam: Request timeout ke {SPAM_PREDICT_API_URL}")
        return {"error": "API Spam timeout."}
    except requests.exceptions.RequestException as e:
        print(f"Error API Spam: Tidak bisa terhubung atau request gagal - {e}")
        return {"error": f"Gagal menghubungi API Spam: {str(e)}"}
    except json.JSONDecodeError:
        print(f"Error API Spam: Respons bukan JSON valid.")
        # print(f"Raw Response: {response.text if 'response' in locals() else 'N/A'}")
        return {"error": "Respons API Spam tidak valid."}

# --- Endpoint FastAPI ---
@app.get("/status") # Path endpoint-nya adalah /status
async def get_status():
    return {"status": "API is running"}

@app.post("/process_screenshot/")
async def process_screenshot(image: UploadFile = File(...)):
    """
    Endpoint untuk memproses screenshot:
    1. Menerima file gambar.
    2. Melakukan OCR.
    3. Mengirim teks OCR ke Gemini untuk ekstraksi URL dan teks SMS.
    4. Mengirim teks SMS ke API deteksi spam.
    5. (Future) Mengirim URL ke API deteksi phishing.
    """
    temp_image_path = None
    try:
        # Membuat nama file unik untuk gambar yang diupload
        file_extension = os.path.splitext(image.filename)[1]
        if not file_extension.lower() in ['.png', '.jpg', '.jpeg', '.bmp', '.tiff']:
            raise HTTPException(status_code=400, detail="Format file tidak didukung. Gunakan PNG, JPG, JPEG, BMP, atau TIFF.")

        temp_image_filename = f"{uuid.uuid4()}{file_extension}"
        temp_image_path = os.path.join(TEMP_IMAGE_DIR, temp_image_filename)

        # Menyimpan gambar yang diupload ke path sementara
        with open(temp_image_path, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)

        # 1. Lakukan OCR
        ocr_text = perform_ocr(temp_image_path)
        if ocr_text is None: # perform_ocr sudah raise HTTPException jika ada error fatal
            ocr_text = "" # Jika error minor dan return None tapi tidak raise, anggap teks kosong

        # 2. Ekstrak informasi menggunakan Gemini LLM
        gemini_extraction_results = extract_info_with_gemini(ocr_text)
        if gemini_extraction_results is None:
             # extract_info_with_gemini sudah raise HTTPException jika ada error fatal
            raise HTTPException(status_code=500, detail="Gagal mendapatkan hasil ekstraksi dari LLM.")


        # 3. Proses Deteksi Spam (jika ada konten teks)
        spam_detection_outputs = []
        potential_sms_content = gemini_extraction_results.get("potential_sms_content", "")
        
        # Sesuai modifikasi prompt, potential_sms_content sekarang adalah string tunggal
        if gemini_extraction_results.get("contains_text_content") and potential_sms_content and potential_sms_content.strip():
            print(f"\n[INFO] Konten teks (SMS) terdeteksi. Mengirim ke API Deteksi Spam:")
            print(f"  -> Memproses Teks SMS: '{potential_sms_content[:200]}...'")
            spam_result = detect_spam_via_api(potential_sms_content)
            if spam_result:
                spam_detection_outputs.append({
                    "analysed_text": potential_sms_content,
                    "detection_result": spam_result
                })
            else:
                 spam_detection_outputs.append({
                    "analysed_text": potential_sms_content,
                    "detection_result": {"error": "Gagal mendapatkan hasil deteksi spam dari API."}
                })
        else:
            print("\n[INFO] Tidak ada konten teks (SMS) relevan yang diekstrak oleh Gemini untuk deteksi spam.")


        # 4. Proses Deteksi Phishing (Placeholder untuk implementasi selanjutnya)
        phishing_detection_outputs = []
        extracted_urls_objects = gemini_extraction_results.get("extracted_urls", [])
        if gemini_extraction_results.get("contains_urls") and extracted_urls_objects:
            print("\n[INFO] URL terdeteksi. (Integrasi deteksi phishing akan menyusul)")
            for url_obj in extracted_urls_objects:
                url_to_check = url_obj.get("url")
                if url_to_check:
                    print(f"  -> URL Ditemukan: {url_to_check}")
                    # Nantinya:
                    # phishing_result = detect_phishing_via_api(url_to_check)
                    # phishing_detection_outputs.append({"url": url_to_check, "detection_result": phishing_result})
                    phishing_detection_outputs.append({
                        "url": url_to_check,
                        "detection_result": {"status": "Phishing detection not yet implemented."}
                    })
        else:
            print("\n[INFO] Tidak ada URL yang diekstrak oleh Gemini.")

        # Gabungkan semua hasil
        final_response = {
            "ocr_output": ocr_text,
            "llm_extraction": gemini_extraction_results,
            "spam_detection_results": spam_detection_outputs,
            "phishing_detection_results": phishing_detection_outputs
        }
        return JSONResponse(content=final_response)

    except HTTPException as http_exc:
        # Re-raise HTTPException agar FastAPI menanganinya
        raise http_exc
    except Exception as e:
        # Tangani error tak terduga lainnya
        print(f"Terjadi error tak terduga di endpoint /process_screenshot: {e}")
        raise HTTPException(status_code=500, detail=f"Terjadi kesalahan internal server: {str(e)}")
    finally:
        # Selalu bersihkan file gambar sementara jika sudah dibuat
        if temp_image_path and os.path.exists(temp_image_path):
            try:
                os.remove(temp_image_path)
                print(f"File sementara {temp_image_path} dihapus.")
            except Exception as e_remove:
                print(f"Gagal menghapus file sementara {temp_image_path}: {e_remove}")

# Jalankan dengan Uvicorn (untuk development lokal):
# uvicorn main:app --reload