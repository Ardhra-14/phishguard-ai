FROM python:3.12-slim-bookworm

WORKDIR /app

# System deps for Playwright + WeasyPrint + OCR (Tesseract)
RUN apt-get update && apt-get install -y --no-install-recommends \
<<<<<<< HEAD
    curl build-essential libpq-dev git \
=======
    curl build-essential libpq-dev \
    tesseract-ocr libgl1 libglib2.0-0 \
>>>>>>> feature/visual-detection
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright Chromium (for visual clone detection in Phase 4)
RUN playwright install chromium --with-deps

# Copy source
COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]