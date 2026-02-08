FROM python:3.11-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1

# Copy and install dependencies first for better caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code after dependencies are installed
COPY app ./app

EXPOSE 9000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9000"]
