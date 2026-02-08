FROM python:3.11-slim
WORKDIR /app

# Copy and install dependencies first for better caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code after dependencies are installed
COPY streamlit_app.py ./

EXPOSE 8501
ENV PYTHONUNBUFFERED=1
CMD ["streamlit", "run", "streamlit_app.py", "--server.address", "0.0.0.0", "--server.port", "8501"]
