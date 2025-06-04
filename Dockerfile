# Dockerfile

# 1. Gunakan base image Python yang sesuai
FROM python:3.11-slim

# 2. Set direktori kerja di dalam container
WORKDIR /app

# 3. Install dependensi sistem: Tesseract OCR dan paket bahasa
# Penting: Pastikan nama paket bahasa sesuai dengan yang dibutuhkan Tesseract di Debian/Ubuntu
# 'tesseract-ocr-eng' untuk Inggris, 'tesseract-ocr-ind' untuk Indonesia
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    tesseract-ocr-ind \
    # libgl1-mesa-glx libglib2.0-0 # Kadang dibutuhkan oleh Pillow/OpenCV jika ada GUI related
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 4. Salin file requirements.txt dan install dependensi Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. Salin semua kode aplikasi ke dalam container
COPY . .

# 6. Expose port yang akan digunakan oleh Uvicorn (Railway akan mengaturnya via $PORT)
# Port ini akan dipetakan oleh Railway ke port publik
EXPOSE 8000 

# 7. Definisikan environment variable default (bisa di-override di Railway)
ENV PYTHONUNBUFFERED=1
# ENV PORT=8000 # Railway akan menyediakan $PORT, jadi ini tidak selalu perlu

# 8. Command untuk menjalankan aplikasi saat container dimulai
# Railway akan menggunakan $PORT yang diinjeksikan.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
# Jika ingin Railway menggunakan $PORT: CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]