FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Garante que o diretório do SQLite exista
RUN mkdir -p /app/data

EXPOSE 5000

# 1 worker com 4 threads garante instância única do APScheduler sem duplicar jobs
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "app:create_app()"]