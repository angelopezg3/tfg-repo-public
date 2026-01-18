"""
Project developed as part of the Trabajo de Fin de Grado (TFG)
Grado en Ingeniería Informática - UNIR

Author: angelopezg3
Year: 2026
License: MIT
"""

import redis
from celery import Celery
from utils import config

"""
    Redis siempre se ejecuta en un docker pero el tasks.py lo podemos ejecutar en local o en docker
    La url de conexión de nuestro código contra redis cambia en función de donde se ejecuta el código.
"""
if config["TASKS_LOCAL"]:
    redis_host="localhost"
else:
    redis_host="redis"

r = redis.Redis(host=redis_host, port=6379, db=0, decode_responses=True)
app = Celery(
    "pcap_tasks",
    # configuración con docker
    broker=f"redis://{redis_host}:6379/0",
    backend=f"redis://{redis_host}:6379/0")
app.conf.timezone = "Europe/Madrid"



# CONFIGURACIÓN PARA TOLERANCIA A FALLOS
app.conf.update(
    # Reiniciar worker después de X tareas para liberar memoria
    worker_max_tasks_per_child=100,

    # Timeouts
    #task_time_limit=72000,  # 20 horas máximo
    #task_soft_time_limit=36000, #10 horas

    # TOLERANCIA A FALLOS: NO hacer ACK hasta que termine, NO PORQUE LAS TAREAS SON LARGAS
    # para determinar si los workers murieron tengo el heartbeat
    #task_acks_late=True,  # ACK después de completar, no antes
    #task_reject_on_worker_lost=True,  # Reencolar si worker muere

    # Retry automático
    task_autoretry_for=(Exception,),  # Reintentar en cualquier excepción
    task_retry_kwargs={'max_retries': 3, 'countdown': 60},  # 3 reintentos, esperar 1 min

    # Prefetch
    worker_prefetch_multiplier=1,
    # cada proceso del worker solo procesa una tarea a la vez, asegura el orden correcto de procesado
    # Ejemplo: Cola: [T1, T2, T3, T4, T5, T6, T7, T8]
    # worker con 3 procesos (-c 3).
    # Proceso 1: T1  --> T1 terminado, luego T4
    # Proceso 2: T2  --> T2 terminado, luego T5
    # Proceso 3: T3  --> T3 terminado, luego T6

    # Pool settings
    #worker_pool_restarts=True,

    # Visibilidad de tareas
    #result_expires=86400,  # Resultados expiran en 24h

    # Tracking de estado
    task_track_started=True,  # Marcar tareas como STARTED
    task_send_sent_event=True,  # Enviar eventos para flower
)
