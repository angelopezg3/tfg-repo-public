#!/bin/bash
# ================================
# Inicia captura con dumpcap en Android (vía Termux)
# Crea carpeta /sdcard/captures y genera nombre con milisegundos
# ================================

INPUT_SIZE_MB=${1:-1}  # Si no se pasa parámetro, valor por defecto 1 MB


# === CONFIGURACIÓN ===
CAPTURE_DIR="/sdcard/captures"
DUMPCAP="/data/data/com.termux/files/usr/bin/dumpcap"
FILE_SIZE_KB=$((INPUT_SIZE_MB * 1024))      # 1 MB por defecto (dumpcap usa KB)
MAX_FILES=100           # Máximo de archivos rotados

# === CREAR DIRECTORIO SI NO EXISTE===
mkdir -p "$CAPTURE_DIR"
chmod 777 "$CAPTURE_DIR"

# === CAPTURA ===
echo "Iniciando captura..."
echo "Destino base: $CAPTURE_DIR/captura_${ts}.pcap"
echo "Tamaño máximo por archivo: $INPUT_SIZE_MB MB ($FILE_SIZE_KB KB)"

# -i any: todas las interfaces
# -b filesize: rotación por tamaño (en KB)
# -b files: máximo número de archivos
su - termux -c "/data/data/com.termux/files/usr/bin/dumpcap -i any -b filesize:$FILE_SIZE_KB -b files:$MAX_FILES -w $CAPTURE_DIR/captura.pcap"
