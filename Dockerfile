FROM python:3.11-slim

WORKDIR /app

# instalar tshark y dependencias necesarias
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    tshark \
    wireshark-common \
    libglib2.0-0 \
    libpcap0.8 \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
#ENV PIP_DEFAULT_TIMEOUT=120
RUN pip install --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
