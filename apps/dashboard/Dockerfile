FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt
COPY streamlit_app.py ./
COPY mitre_attack_mapping.json ./
EXPOSE 8501
ENV PYTHONUNBUFFERED=1
CMD ["streamlit", "run", "streamlit_app.py", "--server.address", "0.0.0.0", "--server.port", "8501"]
