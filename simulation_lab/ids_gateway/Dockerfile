FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY engine.py app.py index.html /app/

EXPOSE 8501
EXPOSE 8443
EXPOSE 8080

CMD ["python", "-u", "app.py"]
