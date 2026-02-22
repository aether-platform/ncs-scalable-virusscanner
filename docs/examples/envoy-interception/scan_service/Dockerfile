FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Install the package in editable mode for development
RUN pip install --no-cache-dir -e .[all]

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src

CMD ["scan-producer"]
