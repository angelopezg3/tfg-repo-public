"""
Project developed as part of the Trabajo de Fin de Grado (TFG)
Grado en Ingeniería Informática - UNIR

Author: angelopezg3
Year: 2026
License: MIT
"""

from datetime import datetime, timedelta
import time as pytime
from pathlib import Path
import requests
from bs4 import BeautifulSoup
import csv
from utils import logger,config
from requests.exceptions import ConnectionError, Timeout, TooManyRedirects, RequestException

memory_cache_expiration = config["ANDROID_DEVICES_MEMORY_CACHE_EXPIRATION_SECONDS"]  # segundos
_last_load = 0
_android_models_cache = None


def load_android_models():
    """
    Carga el catálogo oficial de Android.
    Si existe el CSV local, lo usa mientras no haya expirado, si no existe o ha expirado lo descarga desde la url de google.
    Esta función se invoca con un celery beat según la config de beat_schedule.py o desde read_android_cache_file si no
    existe el fichero local cuando un proceso vaya a usarlo.

    """
    need_download = True
    local_cache = config["ANDROID_DEVICES_CACHE_FILE"]
    expiration_days = config["ANDROID_DEVICES_CACHE_EXPIRATION_DAYS"]

    if Path(local_cache).exists():
        # Revisar fecha de modificación del archivo
        mtime = datetime.fromtimestamp(Path(local_cache).stat().st_mtime)
        if datetime.now() - mtime < timedelta(days=expiration_days):
            need_download = False

    if not need_download:
        # Usar CSV local
        with Path(local_cache).open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return {
                r["Model"].strip().upper(): f"{r['Retail Branding']} {r['Marketing Name']}".strip()
                for r in reader
            }

    # Descargar CSV de Google Play
    logger.debug("Descargando catalogo oficial de modelos Android...")
    url = config["ANDROID_DEVICES_CACHE_FILE_SOURCE"]
    timeout= config["ANDROID_DEVICES_REQUEST_TIMEOUT_SECS"]
    mapping = {}

    try:
        r = requests.get(url, timeout=timeout)
        logger.debug("Catalogo oficial de modelos Android descargado")
    except Timeout:
        # 1. Manejo específico para timeouts (si la conexión se establece pero es lenta)
        logger.error(f"Error de tiempo de espera (Timeout) al descargar {url}. El servidor no respondió a tiempo.")
        return mapping
    except ConnectionError as e:
        # 2. Manejo de errores de conexión (incluyendo tu NameResolutionError/DNS)
        # Esto captura la 'MaxRetryError' causada por la 'NameResolutionError'
        logger.error(f"Error de conexión (DNS o Red) al descargar el catálogo Android. Host: {url} | Error: {e}")
        return mapping
    except RequestException as e:
        # 3. Manejo de otros errores de la librería requests (e.g., errores SSL, TooManyRedirects)
        logger.error(f"Error general en la solicitud de requests: {e}")
        return mapping
    except Exception as e:
        # 4. Manejo de cualquier otro error inesperado
        logger.exception(f"Error inesperado al intentar actualizar el catálogo: {e}")
        return mapping

    soup = BeautifulSoup(r.text, "html.parser")

    table = soup.find("table")
    if not table:
        return mapping

    headers = [th.text.strip() for th in table.find_all("th")]

    for row in table.find_all("tr")[1:]:  # saltar cabecera
        cols = [td.text.strip() for td in row.find_all("td")]
        if len(cols) != len(headers):
            continue
        data = dict(zip(headers, cols))
        model_code = data.get("Model", "").upper()
        name = f"{data.get('Retail Branding', '')} {data.get('Marketing Name', '')}".strip()
        if model_code:
            mapping[model_code] = name

    # Guardar copia local
    with Path(local_cache).open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Retail Branding", "Marketing Name", "Device", "Model", "Name"])
        for code, name in mapping.items():
            writer.writerow([name.split()[0], " ".join(name.split()[1:]), "", code, ""])
    logger.debug("Catalogo oficial de modelos Android descargado y procesado. Creada cache local en fichero.")

    return mapping


def read_android_cache_file(local_cache):
    """
    Lee el CSV de modelos Android ya descargado.
    En el caso de que no existiera se descargaría (no debería pasar ya que existe un proceso diario de comprobación
    y descarga si fuera necesario
    """
    path = Path(local_cache)
    if not path.exists():
        logger.warning(f"No se encuentra la cache Android: {path}")
        load_android_models()
        path = Path(local_cache)
        if not path.exists():
            logger.error("Error obteniendo cache de dispositivos Android")

    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        logger.debug("Cargando cache de dispositivos Android")
        return {
            r["Model"].strip().upper(): f"{r['Retail Branding']} {r['Marketing Name']}".strip()
            for r in reader
        }

def get_android_models():
    """
    Lee los modelos de la cache de memoria temporal salvo que haya expirado en cuyo caso va al fichero a recargar la info.
    """
    global _last_load, _android_models_cache
    if pytime.time() - _last_load > memory_cache_expiration or _android_models_cache is None:
        _android_models_cache = read_android_cache_file(config["ANDROID_DEVICES_CACHE_FILE"])
        _last_load = pytime.time()
    return _android_models_cache


if __name__ == "__main__":
    load_android_models()