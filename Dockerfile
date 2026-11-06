FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY *.html ./
COPY styles.css main.js ./
RUN mkdir -p /app/data && useradd -m forum && chown -R forum:forum /app/data
USER forum
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers"]
