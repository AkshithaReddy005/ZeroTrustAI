FROM python:3.11-slim
WORKDIR /app

# Copy and install dependencies first for better caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code after dependencies are installed
COPY app.py ./

ENV PYTHONUNBUFFERED=1
CMD ["python", "app.py"]
