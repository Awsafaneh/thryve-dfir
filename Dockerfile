FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -r requirements.txt && mkdir -p /app/data
EXPOSE 8080
CMD ["python", "app.py", "--no-browser"]
