"""
Project developed as part of the Trabajo de Fin de Grado (TFG)
Grado en Ingeniería Informática - UNIR

Author: angelopezg3
Year: 2026
License: MIT
"""

import gc
from datetime import time, datetime, timedelta
import json
import string
import psutil
import os
import subprocess
import sys
import logging
from concurrent_log_handler import ConcurrentRotatingFileHandler
from pathlib import Path


def load_config():
    # Ruta absoluta basada en la ubicación de este archivo
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
    if not os.path.exists(CONFIG_PATH):
        logger.error(f"Archivo {CONFIG_PATH} no encontrado.Finalizando ejecución.")
        exit()
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)


def setup_logger(config):
    """
    Configura logger con rotación por tamaño (LOG_SIZE_MBS MB)
    compresión automática y compatibilidad multiproceso.
    """
    log_dir = config.get("LOG_DIR", "./logs")
    log_level = getattr(logging, config.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
    os.makedirs(log_dir, exist_ok=True)

    base_log_file = os.path.join(log_dir, "app.log")
    my_logger = logging.getLogger("AppLogger")
    my_logger.setLevel(log_level)
    my_logger.propagate = False

    if not my_logger.handlers:
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(filename)s:%(funcName)s - %(message)s")

        # --- Handler concurrente con rotación por tamaño ---
        file_handler = ConcurrentRotatingFileHandler(
            base_log_file,
            maxBytes= config["LOG_SIZE_MBS"] * 1024 * 1024,
            backupCount=30,
            encoding="utf-8"
        )

        file_handler.setFormatter(formatter)
        my_logger.addHandler(file_handler)

        # --- Handler de consola ---
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        my_logger.addHandler(console_handler)

    # --- Reducir ruido ---
    logging.getLogger("kombu").setLevel(logging.WARNING)
    logging.getLogger("celery").setLevel(logging.INFO)

    return my_logger

# Función helper para parsear fechas con diferentes formatos
def parse_datetime(date_str):
    """Intenta parsear una fecha en formato ISO o con espacio"""
    try:
        # Intentar formato ISO estándar
        return datetime.fromisoformat(date_str)
    except ValueError:
        # Si falla, intentar reemplazar espacio por 'T'
        return datetime.fromisoformat(date_str.replace(' ', 'T'))


def check_memory_usage():
    """Verifica el uso de memoria del proceso actual"""
    process = psutil.Process(os.getpid())
    memory_mb = process.memory_info().rss / 1024 / 1024
    return memory_mb

def force_garbage_collection():
    """Fuerza recolección de basura y libera memoria"""
    gc.collect()

def safe_snippet(raw: bytes, max_len: int = 200) -> str:
    """
    convierte un payload en texto eliminando caracteres no imprimibles y saltos, tabuladores...
    """
    snippet = raw[:max_len]
    try:
        # Decodifica a texto ignorando errores
        snippet_str = snippet.decode("utf-8", errors="ignore")
    except Exception:
        # Si falla, usa la representación segura
        snippet_str = repr(snippet)

    # Elimina saltos de línea y caracteres no imprimibles
    printable = set(string.printable)
    snippet_clean = ''.join(ch for ch in snippet_str if ch in printable)

    # Reemplaza tabulaciones o retornos con espacios
    snippet_clean = snippet_clean.replace("\n", " ").replace("\r", " ").replace("\t", " ")

    return snippet_clean.strip()


def ensure_pcap(path: Path,job_id):
    """
    Detecta si el archivo es SNOOP y lo convierte a PCAP si es necesario.
    Devuelve la ruta del archivo final compatible con Scapy.
    """
    # Leer primeros 8 bytes → suficiente para detectar formato SNOOP
    with open(path, "rb") as f:
        magic = f.read(8)

    # Formato SNOOP empieza con ASCII: b"snoop\0\0\0\0"
    if magic.startswith(b"snoop"):
        logger.debug(f" job:{job_id}: Archivo SNOOP detectado → {path}. Convirtiendo...")
        new_path = path.with_suffix(path.suffix + ".pcap")
        # Si existía un archivo previo convertido, lo eliminamos
        if new_path.exists():
            new_path.unlink()

        print(f"job:{job_id}: Convirtiendo a PCAP: {str(new_path)}")

        # Conversión MUY rápida usando editcap (Wireshark)
        subprocess.run(
            ["editcap", "-F", "pcap", str(path), str(new_path)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return new_path,True

    # Si no es SNOOP, devolvemos el archivo tal cual
    return path,False


config = load_config()
logger = setup_logger(config)
for h in logger.handlers:
    print(">> Handler:", type(h), "->", getattr(h, "baseFilename", None))