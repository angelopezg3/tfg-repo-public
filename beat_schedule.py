"""
Project developed as part of the Trabajo de Fin de Grado (TFG)
Grado en Ingeniería Informática - UNIR

Author: angelopezg3
Year: 2026
License: MIT
"""

from celery.schedules import crontab
from datetime import datetime, timedelta
import gzip
import shutil
from device_detector.parser.operating_system import os

import tasks
from celery_app import app
from utils import os,config,logger
import android_models_cache
import glob



app.conf.beat_schedule = {
    "actualizar-catalogo-diariamente": {
        "task": "beat_schedule.actualizar_catalogo_android",
        "schedule": crontab(hour=3, minute=7),  # cada día a las 03:00
        #"schedule": crontab(minute=50),  # cada hora en el minuto 50
        #"schedule": crontab(),  # cada minuto
        "options": {"queue": "maintenance"},
    },
    "check-jobs": {
        "task": "beat_schedule.recover_active_jobs",
        "schedule": crontab(minute=20),  # cada hora en el minuto 20
        "options": {"queue": "maintenance"},
    },
    "compress-and-clean-logs":{
        "task": "beat_schedule.compress_and_clean_logs",
        "schedule": crontab(),  # cada minuto
        "options": {"queue": "maintenance"},
    }
}
app.conf.timezone = "Europe/Madrid"

if not config["TASKS_LOCAL"]:
    worker_name = os.getenv("CELERY_WORKER_NAME", "unknown")
    if worker_name == "maintenance-worker":
        logger.info(f"Worker  {worker_name} Beat schedule cargado: {app.conf.beat_schedule}")
else:
    logger.info(f"Beat schedule cargado: {app.conf.beat_schedule}")


@app.task(name="beat_schedule.actualizar_catalogo_android")
def actualizar_catalogo_android():
    """Tarea periódica que actualiza el catálogo Android."""
    logger.info("Actualizando catalogo Android con tarea periodica...")
    try:
        mapping = android_models_cache.load_android_models()
        logger.info(f"Catalogo actualizado: {len(mapping)} modelos.")
    except Exception as e:
        logger.error(f"Error actualizando catálogo Android: {e},",exc_info=True)

@app.task(name="beat_schedule.recover_active_jobs")
def recover_active_jobs():
    tasks.recover_active_jobs_logic()

@app.task(name="beat_schedule.compress_and_clean_logs")
def compress_and_clean_logs():
    """
        Rotación de logs:
        1. Procesa archivos temporales generados por ConcurrentRotatingFileHandler.
        2. Genera nombre final con fecha (y contador si hay duplicados).
        3. Comprime a .gz.
        """
    log_dir = config.get("LOG_DIR", "./logs")
    # Buscar logs temporales
    temp_logs = glob.glob(os.path.join(log_dir, "app.log.rotate.*"))
    numbered_logs = glob.glob(os.path.join(log_dir, "app.log.[0-9]*"))
    numbered_logs = [f for f in numbered_logs if not f.endswith('.gz')]
    all_logs= temp_logs+numbered_logs

    for temp_file in all_logs:
        try:
            date_str = datetime.now().strftime("%Y-%m-%d")
            final_name = os.path.join(log_dir, f"app.log.{date_str}")
            final_name_gz = f"{final_name}.gz"

            # Evitar sobrescribir si ya existe
            counter = 1
            while os.path.exists(final_name) or os.path.exists(final_name_gz):
                final_name = os.path.join(log_dir, f"app.log.{date_str}_{counter}")
                final_name_gz= f"{final_name}.gz"
                counter += 1

            # Renombrar
            os.rename(temp_file, final_name)

            # Comprimir
            with open(final_name, "rb") as f_in:
                with gzip.open(f"{final_name}.gz", "wb", compresslevel=9) as f_out:
                    shutil.copyfileobj(f_in, f_out)

            # Borrar el original
            os.remove(final_name)

            logger.info(f"Log rotado y comprimido: {final_name}.gz")

        except Exception as e:
            logger.error(f"Error rotando log {temp_file}: {e}",exc_info=True)

    # limpieza de logs antiguos
    try:
        cutoff_date = datetime.now() - timedelta(days=config["OLD_LOGS_KEEP_DAYS"])
        old_logs = glob.glob(os.path.join(log_dir, "app.log.*.gz"))

        for log_file in old_logs:
            try:
                # Obtener fecha del archivo
                file_stat = os.stat(log_file)
                file_mtime = datetime.fromtimestamp(file_stat.st_mtime)

                if file_mtime < cutoff_date:
                    os.remove(log_file)
                    logger.info(f"Borrado log viejo: {log_file} (edad: {(datetime.now() - file_mtime).days} dias)")

            except Exception as e:
                logger.error(f"Error borrando log viejo {log_file}: {e}")

    except Exception as e:
        logger.error(f"Error limpiando logs viejos: {e}", exc_info=True)

if __name__ == "__main__":
    compress_and_clean_logs()