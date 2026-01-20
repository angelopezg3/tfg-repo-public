"""
Project developed as part of the Trabajo de Fin de Grado (TFG)
Grado en Ingeniería Informática - UNIR

Author: angelopezg3
Year: 2026
License: MIT

Módulo para el API Rest de provisión/gestión de trabajos
"""

from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from celery import Celery, states
from celery.result import AsyncResult
import time as pytime
from pathlib import Path
import redis
import uuid
import tasks
from datetime import datetime
from utils import config, logger

# url doc Swagger interactivo http://localhost:5000/docs
# url doc alternativa http://localhost:5000/redoc

# ===============================
# CONFIGURACIÓN INICIAL
# ===============================
LOCAL_CAP_ROOT = Path(__file__).parent / "pcaps"

# Redis: cambiar host según entorno
redis_host = "localhost" if config["API_LOCAL"] else "redis"
r = redis.Redis(host=redis_host, port=6379, db=0, decode_responses=True)

# Celery app (para enviar y consultar tareas)
celery_app = Celery(
    "pcap_tasks",
    broker=f"redis://{redis_host}:6379/0",
    result_backend=f"redis://{redis_host}:6379/0"
)

# Inicializamos FastAPI
app = FastAPI(
    title="Jobs API",
    description="API para gestionar jobs que procesan carpetas de PCAP mediante Celery y Redis.",
    version="1.0"
)

# Diccionario local para reconstruir jobs activos
jobs = {}


# ===============================
# MODELOS Pydantic
# ===============================

class JobCreate(BaseModel):
    folder: str
    start: datetime
    end: datetime


class JobUpdate(BaseModel):
    start: Optional[datetime] = None
    end: Optional[datetime] = None


# ===============================
# FUNCIONES AUXILIARES
# ===============================

def rebuild_jobs_from_redis():
    """
    Reconstruye el diccionario local de 'jobs' desde Redis al arrancar el API.
    """
    logger.info("Reconstruyendo jobs desde Redis...")
    global jobs
    jobs = {}
    for key in r.scan_iter("job:*:task_id"):
        job_id = key.split(":")[1]
        task_id = r.get(key)
        if task_id:
            jobs[job_id] = AsyncResult(task_id, app=celery_app)
            logger.debug(
                f"Recreado job {job_id} con task_id {task_id}, ready {jobs[job_id].ready()} y celery_status {jobs[job_id].status}")
    logger.info("Reconstruccion finalizada.")


# ===============================
# ENDPOINTS
# ===============================

@app.post("/jobs")
def add_job(req: JobCreate):
    """
    Crea un nuevo job y lo encola en Redis para que celery lo procese.
    Un job es un objeto lógico que almacenamos en REDIS(broker) y que se procesa por una worker(celery) con un task_id concreto.
    Un worker puede tener varias tareas en paralelo pero en nuestro caso solo va a tener una.
    Para monitorizar varias carpetas se crean varios workers, y cada worker tiene una única tarea para procesar en orden.

    Limitaciones con las fechas:
        * fecha de start del job no puede ser anterior a ahora
        * fecha de end del job no puede ser anterior a ahora
        * fecha de start no puede ser anterior a end

    POST /jobs
    {
      "folder": "/pcaps/carpeta1",
      "start": "2025-09-24 10:00:00",
      "end":   "2025-09-24 11:00:00"
    }
    Args:
        req:

    """
    if config["API_LOCAL"]:
        folder_param = req.folder
        subfolder_name = Path(folder_param).name
        folder_path = LOCAL_CAP_ROOT / subfolder_name
    else:
        folder_path = Path(req.folder)

    # Validación de carpeta
    if not folder_path.exists() or not folder_path.is_dir():
        raise HTTPException(status_code=400, detail=f"Carpeta no encontrada: {folder_path}")

    folder = str(req.folder)
    job_id = str(uuid.uuid4())

    # Comprobar duplicados (que ya exista un job monitorizando la misma carpeta)
    for key in r.scan_iter("job:*:folder"):
        existing_folder = r.get(key)
        existing_job = key.split(":")[1]
        stop_flag = r.get(f"job:{existing_job}:stop")
        ready_flag = r.get(f"job:{existing_job}:ready")
        if existing_folder == folder and stop_flag == "0" and not (ready_flag and ready_flag == "1"):
            raise HTTPException(status_code=409, detail=f"Ya existe un job activo para {folder}")

    if req.start:
        try:
            start_dt = datetime.fromisoformat(str(req.start))
        except ValueError:
            raise HTTPException(status_code=400, detail="start no tiene formato ISO válido")

        if start_dt < datetime.now():
            logger.warning(f"Intento de crear job {job_id} con fecha de inicio pasada ({start_dt})")
            raise HTTPException(
                status_code=400,
                detail="No se puede crear un job con fecha de start pasada"
            )
    if req.end:
        try:
            end_dt = datetime.fromisoformat(str(req.end))
        except ValueError:
            raise HTTPException(status_code=400, detail="end no tiene formato ISO válido")

        if end_dt < datetime.now():
            logger.warning(f"Intento de crear job {job_id} con fecha de fin pasada ({end_dt})")
            raise HTTPException(
                status_code=400,
                detail="No se puede crear un job con fecha de fin pasada"
            )
    if req.start and req.end:
        try:
            start_dt = datetime.fromisoformat(str(req.start))
            end_dt = datetime.fromisoformat(str(req.end))
        except ValueError:
            raise HTTPException(status_code=400, detail="start/end no tiene formato ISO válido")
        if end_dt <= start_dt:
            logger.warning(
                f"Intento de crear job {job_id} con fecha de fin {end_dt} menor o igual que la de start ({start_dt})")
            raise HTTPException(
                status_code=400,
                detail="No se puede crear un job con fecha de fin menor o igual que la de start"
            )

    # Guardar metadatos en Redis
    r.set(f"job:{job_id}:start", str(req.start))
    r.set(f"job:{job_id}:end", str(req.end))
    r.set(f"job:{job_id}:stop", "0")
    r.set(f"job:{job_id}:folder", folder)

    # Encolar tarea Celery
    task = celery_app.send_task("tasks.process_job", args=[job_id, folder, str(req.start), str(req.end)], queue="pcaps")
    jobs[job_id] = task
    r.set(f"job:{job_id}:task_id", task.id)

    logger.info(
        f"Job {job_id} creado con task_id {task.id}, start {str(req.start)}, end {str(req.end)} y folder {folder}")

    return {
        "job_id": job_id,
        "task_id": task.id,
        "folder": folder,
        "start": req.start,
        "end": req.end,
        "message": "Job creado correctamente"
    }


@app.get("/jobs")
def list_jobs():
    """Lista todos los jobs activos (ignora los finalizados)."""
    active_jobs = {}

    for key in r.scan_iter("job:*:task_id"):
        job_id = key.split(":")[1]
        task_id = r.get(key)
        if not task_id:
            continue

        job = AsyncResult(task_id, app=celery_app)
        ready_flag = r.get(f"job:{job_id}:ready")
        if ready_flag and ready_flag.lower() in ("true", "1"):
            continue

        active_jobs[job_id] = {
            "celery_status": job.status,
            "job_state": r.get(f"job:{job_id}:job_state"),
            "start": r.get(f"job:{job_id}:start"),
            "end": r.get(f"job:{job_id}:end"),
            "folder": r.get(f"job:{job_id}:folder"),
            "stop": r.get(f"job:{job_id}:stop"),
            "task_id": task_id,
            "files_processed": r.get(f"job:{job_id}:files_processed"),
            "task_started_at": r.get(f"job:{job_id}:task_started_at"),
            "task_finished_at": r.get(f"job:{job_id}:task_finished_at"),
            "heartbeat": r.get(f"job:{job_id}:heartbeat"),
        }

    return active_jobs


@app.get("/jobs/{job_id}")
def get_job(job_id: str):
    """Obtiene el estado detallado de un job."""
    """
        Explicación celery_status, ready y result
        celery_status
            Es el estado interno que Celery asigna a la tarea.
            Puede tomar valores como:
                "PENDING" → La tarea aún no se ha ejecutado (está en la cola).
                "STARTED" → La tarea está siendo ejecutada por un worker.
                "SUCCESS" → La tarea finalizó correctamente.
                "FAILURE" → La tarea terminó con error.
                "REVOKED" → La tarea fue revocada antes o durante la ejecución.
        ready()
            Es un metodo que devuelve True/False indicando si la tarea ya terminó de cualquier manera.
            Retorna True cuando la tarea está:
                "SUCCESS"
                "FAILURE"
                "REVOKED"
            Retorna False si la tarea está "PENDING" o "STARTED".
        result
            Contiene el valor devuelto por la tarea o la excepción que ocurrió si falló.
            Depende de ready():
                Si ready() == True y la tarea tuvo éxito → result es el valor retornado por la función.
                Si la tarea falló → result es la excepción (Exception o TaskRevokedError).
                Si la tarea no terminó aún → no acceder a result (puede ser None o causar errores).

    """

    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job no encontrado")

    task_id = r.get(f"job:{job_id}:task_id")
    res = AsyncResult(task_id, app=celery_app)
    ready_flag = r.get(f"job:{job_id}:ready")

    status = {
        "celery_status": res.status,
        "job_state": r.get(f"job:{job_id}:job_state"),
        "ready": res.ready(),
        "result": None if not res.ready() else res.result,
        "start": r.get(f"job:{job_id}:start"),
        "end": r.get(f"job:{job_id}:end"),
        "folder": r.get(f"job:{job_id}:folder"),
        "stop": r.get(f"job:{job_id}:stop"),
        "task_id": task_id,
        "files_processed": r.get(f"job:{job_id}:files_processed"),
        "task_started_at": r.get(f"job:{job_id}:task_started_at"),
        "task_finished_at": r.get(f"job:{job_id}:task_finished_at"),
        "heartbeat": r.get(f"job:{job_id}:heartbeat"),
    }

    if ready_flag and ready_flag.lower() in ("true", "1"):
        status["message"] = "Job marcado como finalizado"

    return status


@app.patch("/jobs/{job_id}")
def update_job(job_id: str, req: JobUpdate):
    """Actualiza dinámicamente la fecha de start y/o fin de un job.
    PATCH /jobs/<job_id>  body: {"start": "2025-09-24 12:00:00","end": "2025-09-24 12:00:00"}
    Permite actualizar la fecha de start/fin en caliente: el worker lo leerá en pocos segundos.

    Limitaciones con las fechas:
        * fecha de start del job no puede ser anterior a ahora
        * fecha de end del job no puede ser anterior a ahora
        * fecha de start no puede ser anterior a end
         * Si solo se actualiza start → debe ser <= end ya almacenado.
        * Si solo se actualiza end → debe ser >= start ya almacenado.
        * No se puede modificar la fecha de start de un job que ya empezó.
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job no encontrado")

    updated_fields = {}
    original_fields = {}
    now = datetime.now()

    # Recuperar valores actuales almacenados en redis (si existen)
    stored_start = r.get(f"job:{job_id}:start")
    stored_end = r.get(f"job:{job_id}:end")

    original_fields["start"] = stored_start
    original_fields["end"] = stored_end

    stored_start_dt = datetime.fromisoformat(stored_start) if stored_start else None
    stored_end_dt = datetime.fromisoformat(stored_end) if stored_end else None

    # Validación simultánea si se envían ambas fechas
    if req.start and req.end:
        try:
            start_dt = datetime.fromisoformat(str(req.start))
            end_dt = datetime.fromisoformat(str(req.end))
        except ValueError:
            raise HTTPException(status_code=400, detail="start o end no tiene formato ISO válido")

        if start_dt < now:
            logger.warning(f"[{job_id}] Intento inválido: start {start_dt} es anterior a ahora ({now})")
            raise HTTPException(status_code=400, detail="La fecha de inicio no puede ser anterior a ahora")

        if end_dt < now:
            logger.warning(f"[{job_id}] Intento inválido: end {end_dt} es anterior a ahora ({now})")
            raise HTTPException(status_code=400, detail="La fecha de fin no puede ser anterior a ahora")

        if end_dt <= start_dt:
            logger.warning(f"[{job_id}] Intento inválido: end {end_dt} ≤ start {start_dt}")
            raise HTTPException(status_code=400, detail="La fecha de fin no puede ser menor o igual que la de inicio")

        # Si el job ya empezó, no se puede modificar el start
        job_start = r.get(f"job:{job_id}:start")
        try:
            start_dt = datetime.fromisoformat(str(req.start))
        except ValueError:
            raise HTTPException(status_code=400, detail="start no tiene formato ISO válido")
        logger.debug(f"start{start_dt} now{now}")
        if start_dt < now:
            logger.warning(
                f"[{job_id}] Intento inválido: se intentó modificar start tras haber empezado el job (start={job_start})")
            raise HTTPException(status_code=400,
                                detail="No se puede modificar la fecha de inicio de un job que ya empezó")

        r.set(f"job:{job_id}:start", str(req.start))
        r.set(f"job:{job_id}:end", str(req.end))
        updated_fields["start"] = str(req.start)
        updated_fields["end"] = str(req.end)

    # Solo actualiza la fecha de inicio
    elif req.start:
        try:
            start_dt = datetime.fromisoformat(str(req.start))
        except ValueError:
            raise HTTPException(status_code=400, detail="start no tiene formato ISO válido")

        # 1 No puede ser anterior a ahora
        if start_dt < now:
            logger.warning(f"[{job_id}] Intento inválido: start {start_dt} es anterior a ahora ({now})")
            raise HTTPException(status_code=400,
                                detail="No se puede modificar la fecha de inicio a un momento anterior a ahora")

        # 2️ Si el job ya empezó, no se puede modificar el start
        # Si el job ya empezó, no se puede modificar el start
        job_start = r.get(f"job:{job_id}:start")
        try:
            start_dt = datetime.fromisoformat(str(req.start))
        except ValueError:
            raise HTTPException(status_code=400, detail="start no tiene formato ISO válido")
        logger.debug(f"start{start_dt} now{now}")
        if start_dt < now:
            logger.warning(
                f"[{job_id}] Intento inválido: se intentó modificar start tras haber empezado el job (start={job_start})")
            raise HTTPException(status_code=400,
                                detail="No se puede modificar la fecha de inicio de un job que ya empezó")

        # 3️ Si hay una fecha de fin guardada, start no puede ser posterior a end
        if stored_end_dt and start_dt > stored_end_dt:
            logger.warning(f"[{job_id}] Intento inválido: start {start_dt} posterior al end existente {stored_end_dt}")
            raise HTTPException(status_code=400,
                                detail="La fecha de inicio no puede ser posterior a la fecha de fin existente")

        r.set(f"job:{job_id}:start", str(req.start))
        updated_fields["start"] = str(req.start)

    # Solo actualiza la fecha de fin
    elif req.end:
        try:
            end_dt = datetime.fromisoformat(str(req.end))
        except ValueError:
            raise HTTPException(status_code=400, detail="end no tiene formato ISO válido")

        # 1️ No puede ser anterior a ahora
        if end_dt < now:
            raise HTTPException(status_code=400,
                                detail="No se puede modificar la fecha de fin a un momento anterior a ahora. Usa /stop para parar el job.")

        # 2️ Si hay start almacenado, end no puede ser anterior a start
        if stored_start_dt and end_dt < stored_start_dt:
            raise HTTPException(status_code=400,
                                detail="La fecha de fin no puede ser anterior a la fecha de inicio existente")

        r.set(f"job:{job_id}:end", str(req.end))
        updated_fields["end"] = str(req.end)

    else:
        raise HTTPException(status_code=400, detail="No se ha proporcionado ningún campo para actualizar")

    logger.info(f"Job {job_id} actualizado: de {original_fields} a {updated_fields}")
    return {"msg": "Job actualizado", **updated_fields}


@app.post("/jobs/{job_id}/stop")
def stop_job(job_id: str):
    """Detiene un job temporalmente (stop=1). No revoca el worker, este sigue funcionando pero
    el código no hace nada
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job no encontrado")

    r.set(f"job:{job_id}:stop", "1")
    logger.info(f"Job {job_id} parado")
    return {"msg": "Stop solicitado", "job_id": job_id}


@app.post("/jobs/{job_id}/start")
def start_job(job_id: str):
    """Reanuda un job detenido (stop=0)."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job no encontrado")

    r.set(f"job:{job_id}:stop", "0")
    logger.info(f"Job {job_id} reanudado")
    return {"msg": "Job reanudado", "job_id": job_id}


@app.delete("/jobs/{job_id}")
def delete_job(job_id: str):
    """Revoca y marca como finalizado un job.
        DELETE /jobs/<job_id>
      - Revoca la tarea Celery (si sigue activa)
      - marca job a ready (finalizado)
      - no borramos las entradas de celery para tener info de los jobs ejecutados. Solo marcamos ready a 1
      para ignorarlo en las consultas y procesamiento
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job no encontrado")

    task = jobs[job_id]
    try:
        if not task.ready():
            task.revoke(terminate=True)
            logger.info(f"Tarea {task.id} revocada antes de eliminación.")
    except Exception as e:
        logger.warning(f"No se pudo revocar tarea {task.id}: {e}", exc_info=True)

    r.set(f"job:{job_id}:ready", 1)
    r.set(f"job:{job_id}:job_state", config["JOB_STATE_FINISHED_BY_API"])
    logger.info(f"Job {job_id} marcado como finalizado.")
    return {"message": f"Job {job_id} marcado como finalizado"}


@app.get("/jobs/{job_id}/health")
def check_job_health(job_id: str):
    """Verifica el estado de heartbeat de un worker. Nos da info sobre la salud el job, si esta funcionando
    correctamentne o se ha colgado.
    """
    heartbeat = r.get(f"job:{job_id}:heartbeat")
    if not heartbeat:
        return {
            "job_id": job_id,
            "status": "DEAD",
            "message": "Sin latido o worker inactivo"
        }

    last_heartbeat = datetime.fromisoformat(heartbeat)
    now = datetime.now()
    seconds_ago = (now - last_heartbeat).total_seconds()

    interval = config["HEARTBEAT_INTERVAL"]
    if seconds_ago < interval + 10:
        status, color = "HEALTHY", "🟢"
    elif seconds_ago < interval + 60:
        status, color = "WARNING", "🟡"
    else:
        status, color = "DEAD", "🔴"

    return {
        "job_id": job_id,
        "status": status,
        "icon": color,
        "last_heartbeat": heartbeat,
        "seconds_since_heartbeat": int(seconds_ago)
    }


@app.post("/jobs/recover_active_jobs")
def recover_active_jobs():
    """Ejecuta la lógica de recarga de jobs en celery desde redis"""
    tasks.recover_active_jobs_logic("api")
    return {"msg": "Recover active Jobs ejecutado"}


# ===============================
# ARRANQUE
# ===============================

pytime.sleep(5)  # Esperar a que los workers reconstruyan estado
rebuild_jobs_from_redis()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("jobs_API:app", host="0.0.0.0", port=5000, reload=True)