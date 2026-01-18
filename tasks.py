"""
Project developed as part of the Trabajo de Fin de Grado (TFG)
Grado en Ingeniería Informática - UNIR

Author: angelopezg3
Year: 2026
License: MIT
"""

import time as pytime
from datetime import time,datetime
import os
from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR
from ipaddress import ip_address
from celery.signals import after_setup_logger, worker_process_shutdown
from celery.signals import worker_ready
from celery.result import AsyncResult
from celery.signals import task_prerun, task_postrun  # Nuevos signals
import analyzer
from pathlib import Path
import csv
import android_models_cache
from celery_app import r,app
from utils import config, logger, parse_datetime, check_memory_usage, force_garbage_collection, ensure_pcap
from contextlib import contextmanager

LOCAL_CAP_ROOT = Path(__file__).parent / "pcaps"


# ============================================
# FUNCIONES DE MONITOREO Y MANTENIMIENTO
# ============================================

def update_heartbeat(job_id: str):
    """
    Actualiza heartbeat para indicar que el worker está vivo.
    Expira automáticamente en 2 minutos si no se actualiza.
    """
    try:
        logger.debug(f"job:{job_id}:actualizando heartbeat {datetime.now().isoformat()}")
        r.set(f"job:{job_id}:heartbeat", datetime.now().isoformat())
        r.expire(f"job:{job_id}:heartbeat", 180)  # Expira en 3 minutos
    except Exception as e:
        logger.warning(f"Error actualizando heartbeat para job {job_id}: {e}",exc_info=True)

# ============================================
# FIN FUNCIONES DE MONITOREO
# ============================================

@after_setup_logger.connect
def on_celery_setup_logger(celery_logger, *args, **kwargs):
    """Forzar que cada worker de Celery use nuestro logger personalizado."""
    custom_logger = logger
    # Evitar duplicados: añadir handler solo si no existe
    if not custom_logger.handlers:
        for h in logger.handlers:
            custom_logger.addHandler(h)
    celery_logger.handlers = custom_logger.handlers
    celery_logger.setLevel(custom_logger.level)


def find_capture_files(folder: Path):
    files = []
    for pattern in ("*.pcap", "*.pcapng","*.net"):
        if config["RECURSIVE_SEARCH"]:
            files.extend(folder.rglob(pattern))
        else:
            files.extend(folder.glob(pattern))

    files = [f for f in files if f.is_file()]
    return sorted(files, key=os.path.getmtime)  # de más antiguo a más nuevo


def process_capture_fast(capture_path: Path, output_csv: Path, last_heartbeat, job_id):
    """Versión rápida usando Scapy (streaming)"""
    try:
        snoop_file=False
        logger.debug(f"job:{job_id}:Analizando fichero {capture_path}")
        last_heartbeat = beat(last_heartbeat, job_id)
        original_path=capture_path
        capture_path, snoop_file = ensure_pcap(capture_path,job_id)
        file_name=capture_path.name

        #Cargar todos los ClientHello TLS y construir diccionario frame_number → SNI
        frame_to_sni = analyzer.build_frame_sni_map(str(capture_path),job_id)

        with open(output_csv, "a", newline="") as f:
            writer = csv.writer(f)
            packet_count = 0
            batch = []
            android_models=android_models_cache.get_android_models()

            with PcapReader(str(capture_path)) as pcap_reader:
                for pkt in pcap_reader:
                    packet_count += 1

                    ts_packet = datetime.fromtimestamp(float(pkt.time)).isoformat()

                    src_so=0
                    # Detectar si es IPv4 o IPv6
                    if pkt.haslayer(IP):
                        ip_layer = pkt.getlayer(IP)
                        ttl_number = ip_layer.ttl
                        src = ip_layer.src
                        dst = ip_layer.dst
                        src_so = analyzer.return_ttl_so_name(ttl_number)
                    elif pkt.haslayer(IPv6):
                        ip_layer = pkt.getlayer(IPv6)
                        ttl_number = ip_layer.hlim
                        src = ip_layer.src
                        dst = ip_layer.dst
                        src_so = analyzer.return_ttl_so_name(ttl_number)
                    else:
                        continue  # No IP, ignorar

                    # Si el valor de config OUTGOING_TRAFFIC_ONLY es true solo analizamos las peticiones salientes (las que tienen por origen ip privada)
                    # si es false analizamos todas
                    if ip_address(src).is_private:

                        # -------DNS------
                        dns_layer=pkt.getlayer(DNS)
                        dnsqr_layer=pkt.getlayer(DNSQR)
                        if dns_layer and dnsqr_layer  and getattr(dnsqr_layer, "qname", None):
                            qry = dnsqr_layer.qname.decode(errors="ignore")
                            ts_now= datetime.now().isoformat()
                            batch.append([ts_now,file_name,ts_packet, src, dst,src_so,"DNS", "query", qry])

                        #--------TCP------
                        tcp_layer = pkt.getlayer(TCP)
                        if tcp_layer and tcp_layer.payload:
                            raw = bytes(tcp_layer.payload)
                            #src_port = tcp_layer.sport
                            dst_port = tcp_layer.dport


                            # BUSQUEDA DE CREDENCIALES TCP (HTTP, FTP, etc)
                            batch=analyzer.search_credentials(batch, raw, ts_packet,file_name, src,src_so, dst, dst_port,str(capture_path),packet_count,job_id)

                            # HTTP HOSTs
                            batch=analyzer.search_http_hosts(batch, raw, ts_packet,file_name, src,src_so, dst, job_id)
                            # HTTP User-Agent
                            batch=analyzer.search_user_agent(batch, raw, ts_packet,file_name, src,src_so, dst,  android_models,job_id)
                            # TLS SNI usando diccionario preprocesado
                            if packet_count in frame_to_sni:
                                sni = frame_to_sni[packet_count]
                                ts_now = datetime.now().isoformat()
                                batch.append([ts_now,file_name,ts_packet, src, dst, src_so, "HTTPS", "sni", sni])

                        # --- UDP ---
                        udp_layer = pkt.getlayer(UDP)
                        if udp_layer and udp_layer.payload:
                            dst_port = udp_layer.dport
                            raw = bytes(udp_layer.payload)
                            # STUN sobre UDP
                            batch = analyzer.search_stun_info(batch, raw, ts_packet,file_name, src,src_so, dst,dst_port)
                    else:
                        # en los paquetes entrantes de vuelta, es decir con destino una ip privada...SOLO MIRO EL STUN
                        # --- UDP ---
                        udp_layer = pkt.getlayer(UDP)
                        if udp_layer and udp_layer.payload:
                            dst_port = udp_layer.dport
                            raw = bytes(udp_layer.payload)
                            # STUN sobre UDP
                            batch = analyzer.search_stun_info(batch, raw, ts_packet,file_name, src, "SO Unknown", dst, dst_port)

                    if len(batch) >= 1000:
                        writer.writerows(batch)
                        f.flush()
                        batch.clear()
                        last_heartbeat = beat(last_heartbeat, job_id)


            if batch:
                writer.writerows(batch)
                f.flush()

        # Si snoop file borramos el fichero convertido
        if snoop_file:
            capture_path.unlink()

        if config["MOVE_TO_PROCESSED"]:
            # mover archivo procesado para no reprocesarlo
            processed_dir = capture_path.parent / "processed"
            processed_dir.mkdir(exist_ok=True)
            if snoop_file:
                file_to_move=original_path
            else:
                file_to_move=capture_path
            try:
                file_to_move.rename(processed_dir / file_to_move.name)
            except Exception as e:
                logger.error(f"job:{job_id}:Error moviendo {file_to_move}: {e}")
        else:
            if snoop_file:
                file_to_remove=original_path
            else:
                file_to_remove=capture_path
            # borrar archivo procesado.
            try:
                file_to_remove.unlink()
                logger.debug(f"job:{job_id}:Archivo {capture_path} eliminado tras el procesamiento.")
            except Exception as e:
                logger.warning(f"job:{job_id}:Error al borrar {capture_path}: {e}")

        logger.info(f"job:{job_id}:Procesado {packet_count} paquetes en {capture_path.name}")
        return last_heartbeat

    except Exception as e:
        logger.error(f"job:{job_id}:Error procesando {capture_path}: {e}",exc_info=True)
        last_heartbeat = beat(last_heartbeat, job_id)
        return last_heartbeat

def update_to_started(self,job_id):
    # Comprobar el estado actual
    current_state = self.AsyncResult(self.request.id).state

    #result = AsyncResult(task_id, app=process_job.app)
    #backend_state = result.state

    # Si aún está en PENDING, lo forzamos manualmente a STARTED
    if current_state == 'PENDING':
        self.update_state(state='STARTED')
        logger.info(f"job:{job_id}: estado forzado manualmente a STARTED (task_id={self.request.id})")
    else:
        pass
        #logger.debug(f"job:{job_id}: ya estaba en estado {current_state}, no se fuerza STARTED")

def beat(last_heartbeat, job_id):
    """
    Cuando pasan mas de HEARTBEAT_INTERVAL actualizamos el heartbeat
    """
    current_time=pytime.time()
    if  current_time- last_heartbeat > config["HEARTBEAT_INTERVAL"]:
        update_heartbeat(job_id)
        return current_time
    else:
        return last_heartbeat
    
@app.task(bind=True)
def process_job(self, job_id: str, folder: str, start_iso: str, end_iso: str):
    """
    Worker largo que:
      - comprueba que exista la carpeta a monitorizar (en caso negativo el worker acaba)
      - espera hasta 'start_iso'
      - mientras stop!=1
        - si ahora >= end: espera en modo pausa larga (DEEP_SLEEP_INTERVAL) hasta que se actualize fecha fin o se detenga.
        - si ahora < end procesa archivos
            - busca recursivamente .pcap/.net
            - procesa en orden más antiguo -> más nuevo
            - mueve los procesados a processed si FLAG habilitado
            - duerme SLEEP_INTERVAL y repite
    """
    update_to_started(self,job_id)
    last_heartbeat = pytime.time()

    folder_path= get_folder_path_secure(folder)
    output_csv = folder_path / "pcap_summary.csv"
    logger.debug("process job invocado")

    logger.info(f"job:{job_id}: Iniciando con folder={folder}, start={start_iso}, end={end_iso}")
    logger.info(f"job:{job_id}: Hora actual del servidor: {datetime.now()}")
    logger.info(f"job:{job_id}: Redis end key: {r.get(f'job:{job_id}:end')}")
    logger.info(f"job:{job_id}: Carpeta existe: {folder_path.exists()}")

    # Variable para controlar si estamos en pausa
    is_paused = False
    last_end_dt = None

    files_processed = 0

    # parse start
    try:
        start_dt = parse_datetime(start_iso)
        logger.info(f"job:{job_id}: start time={str(start_dt)}")
    except Exception as e:
        error_msg = f"Job {job_id} error parsing start time '{start_iso}': {e}"
        logger.error(error_msg,exc_info=True)
        return error_msg

    last_start_dt = start_dt  # guardamos referencia para detectar cambios

    # esperar al inicio
    while datetime.now() < start_dt:
        update_redis_state_to("JOB_STATE_START_DATE_NOT_REACHED", job_id)
        # leemos fecha de start dentro del bucle por si se modificara salir
        try:
            start_iso_redis = r.get(f"job:{job_id}:start")
            start_dt = parse_datetime(start_iso_redis)
        except Exception as e:
            error_msg = f"Job {job_id} error parsing start time '{start_iso}': {e}"
            logger.error(error_msg)
            return error_msg
        # si la fecha se ha modificado...
        if start_dt!=last_start_dt:
            logger.info(
            f"job:{job_id}: start modificado de {last_start_dt} a {start_dt}, esperando hora de inicio")
            last_start_dt = start_dt  # guardamos referencia para detectar cambios
        else:
            logger.debug(f"job:{job_id}:esperando a hora de inicio {start_dt}")
            last_heartbeat=beat(last_heartbeat, job_id)
            pytime.sleep(config["START_DATE_WAIT_SLEEP"])

    logger.info(f"job:{job_id}: fecha de inicio {start_dt} alcanzada, iniciando procesamiento")


    # loop principal: la fecha de fin se lee desde Redis (se puede actualizar con la API)
    while True:
        # ========================================
        # HEARTBEAT: Actualizar cada HEARTBEAT_INTERVAL
        # ========================================
        last_heartbeat=beat(last_heartbeat, job_id)

        # leer start en cada iteración por si se modifica
        start_iso_redis = r.get(f"job:{job_id}:start")
        if start_iso_redis:
            try:
                start_dt_redis = parse_datetime(start_iso_redis)
                # si la fecha de start cambió y es futura, esperar de nuevo
                if start_dt_redis != last_start_dt and start_dt_redis<datetime.now():
                    logger.info(
                        f"job:{job_id}: start modificado de {last_start_dt} a {start_dt_redis}, esperando de nuevo")
                    update_redis_state_to("JOB_STATE_START_DATE_NOT_REACHED",job_id)
                    last_start_dt = start_dt_redis

                    # esperar solo si start aún no ha llegado
                    while last_start_dt > datetime.now():
                        logger.debug(f"job:{job_id}: esperando nueva fecha de inicio {last_start_dt}")
                        pytime.sleep(config["START_DATE_WAIT_SLEEP"])
                        # volver a leer Redis dentro del while para detectar cambios
                        start_iso_redis = r.get(f"job:{job_id}:start")
                        try:
                            start_dt_redis = parse_datetime(start_iso_redis)
                            if start_dt_redis!=last_start_dt:
                                if start_dt_redis<datetime.now():
                                    logger.info(f"job:{job_id}: start modificado de {last_start_dt} a {start_dt_redis}, arrancando de nuevo")
                                    last_start_dt = start_dt_redis
                                else:
                                    logger.info(f"job:{job_id}: start modificado de {last_start_dt} a {start_dt_redis}")

                        except Exception:
                            start_dt_redis = datetime.now()

            except Exception as e:
                logger.error(f"job:{job_id}: formato de start inválido en Redis: {start_iso_redis} - {e}",exc_info=True)

        # comprobamos que la carpeta existe (si se borra el worker se elimina).
        if not folder_path.exists():
            logger.warning(f"job:{job_id}: carpeta {folder} eliminada, terminando worker")
            # Marcar como finalizado en Redis
            r.set(f"job:{job_id}:ready", 1)
            r.set(f"job:{job_id}:job_state", config["JOB_STATE_FINISHED"])

            return f"Job {job_id} terminated: folder {folder} was deleted"

        # comprobar stop flag
        if r.get(f"job:{job_id}:stop") == "1":
            if not is_paused:
                logger.info(f"Job {job_id} detenido por API (modo pausa)")
                r.set(f"job:{job_id}:job_state", config["JOB_STATE_STOPPED"])
                is_paused = True
            # Espera hasta que stop cambie a "0"
            while r.get(f"job:{job_id}:stop") == "1":
                logger.debug(f"Job {job_id} en pausa (stop=1), esperando reanudacion...")
                pytime.sleep(config["DEEP_SLEEP_INTERVAL"])
                # Cuando se detecta cambio a "0", reanudar
            logger.info(f"Job {job_id} reanudado por API")
            is_paused = False


        # lee end en cada iteración (valor ISO string)
        end_iso = r.get(f"job:{job_id}:end")
        if not end_iso:
            # si no existe la llave, acabamos
            logger.warning(f"Job {job_id} finished (no end key)")
            r.set(f"job:{job_id}:job_state", config["JOB_STATE_FINISHED_BY_ERROR"])
            return f"Job {job_id} finished (no end key)"
        try:
            end_dt = parse_datetime(end_iso)
        except Exception as e:
            error_msg = f"Job {job_id} invalid end format: {end_iso} - {e}"
            r.set(f"job:{job_id}:job_state", config["JOB_STATE_FINISHED_BY_ERROR"])
            logger.error(error_msg,exc_info=True)
            return error_msg

        # Detectar si la fecha de fin fue actualizada
        if last_end_dt != end_dt:
            if last_end_dt is not None:
                logger.info(f"job:{job_id}: fecha de fin actualizada de {last_end_dt} a {end_dt}")
            last_end_dt = end_dt

        now = datetime.now()
        # comprobar fin ventana
        # Si hemos llegado a fecha de fin entrar en modo pausa
        if now >= end_dt:
            if not is_paused:
                logger.info(f"Job {job_id} alcanzada fecha de fin {end_dt}, entrando en modo pausa")
                is_paused=True
            logger.debug(f"job:{job_id}: en pausa, esperando actualizacion de fecha de fin")
            current = r.get(f"job:{job_id}:job_state")
            if not current or current != config["JOB_STATE_END_DATE_REACHED"]:
                r.set(f"job:{job_id}:job_state", config["JOB_STATE_END_DATE_REACHED"])
            pytime.sleep(config["DEEP_SLEEP_INTERVAL"])
            continue

        # Si estábamos en pausa y ahora now< fecha fin, reanudar
        if is_paused:
            logger.info(f"job:{job_id}: reanudando procesamiento (nueva fecha de fin: {end_dt})")
            r.set(f"job:{job_id}:job_state", config["JOB_STATE_RUNNING"])
            is_paused = False

        # buscar ficheros y procesarlos (los que están, y si llegan más tarde serán procesados en la siguiente iteración)
        try:

            current = r.get(f"job:{job_id}:job_state")
            if not current or current != config["JOB_STATE_RUNNING"]:
                r.set(f"job:{job_id}:job_state", config["JOB_STATE_RUNNING"])

            files = find_capture_files(folder_path)
            logger.debug(f"job:{job_id}: encontrados {len(files)} ficheros a procesar")
            for fpath in files:
                last_heartbeat=beat(last_heartbeat,job_id)
                # antes de procesar, revisar stop/end de nuevo por si cambió
                if r.get(f"job:{job_id}:stop") == "1":
                    logger.info(f"Job {job_id} stopped by API during processing")
                    break
                end_iso = r.get(f"job:{job_id}:end")
                if end_iso and datetime.now() >= parse_datetime(end_iso):
                    logger.info(f"Job {job_id} reached end time during processing")
                    break

                logger.info(f"job:{job_id}: procesando {fpath}")
                # crear cabecera si no existe
                if not output_csv.exists():
                    with open(output_csv, "w", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow(["timestamp", "src_ip", "dst_ip", "protocol", "info_type", "value"])

                size=os.path.getsize(fpath)
                size_kb = size / 1024

                inicio = pytime.perf_counter()
                last_heartbeat = process_capture_fast(fpath, output_csv, last_heartbeat, job_id)
                fin = pytime.perf_counter()
                logger.debug(f"job:{job_id}:Tiempo de procesado {fpath} (peso {size_kb} KB): {fin - inicio:.5f} segundos")
                # ========================================
                # CONTADOR: Incrementar archivos procesados
                # ========================================
                files_processed += 1
                # Guardar progreso en Redis
                r.set(f"job:{job_id}:files_processed", files_processed)

                # ========================================
                # MEMORIA: Verificar cada N archivos
                # ========================================
                if files_processed % config["MEMORY_CHECK_INTERVAL"] == 0:
                    memory_mb = check_memory_usage()
                    logger.info(f"job:{job_id}: {files_processed} archivos procesados, memoria: {memory_mb:.2f} MB")

                    # Si supera el límite, forzar GC
                    if memory_mb > config["MAX_MEMORY_MB"]:
                        logger.warning(
                            f"job:{job_id}: límite de memoria alcanzado ({memory_mb:.2f} MB > {config['MAX_MEMORY_MB']} MB), forzando GC")
                        force_garbage_collection()

        except Exception as e:
            logger.error(f"[process_job] Error listando o procesando ficheros en {folder}: {e}",exc_info=True)
            # Guardar el error en Redis para debugging
            r.set(f"job:{job_id}:last_error", str(e))
            r.set(f"job:{job_id}:last_error_at", datetime.now().isoformat())

        files = find_capture_files(folder_path)
        if len(files)>0:
            # si hay mas ficheros para procesar no dormimos, directamente volvemos a ejecutar
            logger.debug(f"job:{job_id}: existen mas ficheros para procesar {len(files)}. No duermo")
            continue
        else:
            logger.debug(f"job:{job_id}: durmiendo {config['SLEEP_INTERVAL']} segundos")
            pytime.sleep(config["SLEEP_INTERVAL"])

"""
@worker_process_shutdown.connect
def on_child_shutdown(**kwargs):
    logger.debug("Worker hijo se ha terminado/reiniciado", kwargs)
"""
@task_prerun.connect
def task_prerun_handler(sender=None, task_id=None, task=None, args=None, **kwargs):
    """Se ejecuta ANTES de que comience la tarea"""
    if task.name == 'tasks.process_job' and len(args) >= 1:
        job_id = args[0]
        logger.info(f"job:{job_id}: tarea iniciando (task_id={task_id})")
        r.set(f"job:{job_id}:task_started_at", datetime.now().isoformat())


@task_postrun.connect
def task_postrun_handler(sender=None, task_id=None, task=None, args=None, state=None, **kwargs):
    """Se ejecuta DESPUÉS de que termine la tarea (éxito o fallo). La tarea solo debería terminar por petición delete
        del API.
    """
    if task.name == 'tasks.process_job' and len(args) >= 1:
        job_id = args[0]
        logger.info(f"job:{job_id}: tarea finalizada con estado {state}")
        r.set(f"job:{job_id}:task_finished_at", datetime.now().isoformat())

@worker_ready.connect
def recover_active_jobs(sender, **kwargs):
    recover_active_jobs_logic("worker_ready")

@contextmanager
def redis_lock(key: str, timeout: int = 600):
    """
        Lock en Redis para evitar ejecuciones concurrentes de la recuperación de jobs activos.
        Como recover_active_jobs_logic se puede ejecutar por la tarea programada o por el worker_ready.connect hay
        que controlar que no se ejecuta a la vez y pueda generar problemas

    """
    lock_key = f"lock:{key}"
    got_lock = r.set(lock_key, "1", nx=True, ex=timeout)
    try:
        if got_lock:
            yield True
        else:
            yield False
    finally:
        if got_lock:
            r.delete(lock_key)

def recover_active_jobs_logic(source):
    """
    Recupera y relanza jobs activos. Se puede invocar desde el api o automaticamente al iniciar el worker.
    Además existe una tarea de mantenimiento que lo ejecuta cada hora.
    La razón de ser de este metodo es que aunque la info de redis si se persiste no pasa lo mismo con celery.
    Entonces si se cae el celery al arrancar hay que hacer una sincro entre lo que dice redis que debería estar corriendo
    y lo que hay en celery.
    Lógica:
        - Ignorar jobs con ready==True
        - Relanzar jobs si:
            - No tienen task_id
            - Tienen task_id pero no están activos en ningún worker

    Se controla además con un lock que este codigo no se invoque simultáneamente desde varios sitios.
    """


    with redis_lock("recover_active_jobs", timeout=1800) as acquired:
        if not acquired:
            logger.warning("Otro proceso de recuperación ya está ejecutándose. Abortando.")
            return

    if source == "worker_ready":
        if not config["TASKS_LOCAL"]:
            worker_name = os.getenv("CELERY_WORKER_NAME", "unknown")
            if worker_name != "pcap-worker":
                return  # solo el worker principal ejecuta la recuperación, para que no repita con el de maintenance
            else:
                logger.info("=" * 60)
                logger.info(f"Worker {worker_name} iniciado: comprobando jobs activos en Redis...")
                logger.info("=" * 60)
        else:
            logger.info("=" * 60)
            logger.info("Worker iniciado: comprobando jobs activos en Redis...")
            logger.info("=" * 60)
    elif source=="api":
        logger.info("=" * 60)
        logger.info("API Request a recover_active_jobs: comprobando jobs activos en Redis...")
        logger.info("=" * 60)

    relaunched_count = 0
    skipped_count = 0
    error_count = 0

    # Obtener lista de tareas activas reales en los workers
    i = app.control.inspect()
    active_tasks = set()
    try:
        active = i.active() or {}
        for worker, tasks in active.items():
            for t in tasks:
                active_tasks.add(t["id"])
                logger.debug(f"Tarea activa detectada: {t['id']} en {worker}")

    except Exception as e:
        logger.warning(f"No se pudo consultar tareas activas en workers: {e}",exc_info=True)

    logger.info(f"Total de tareas realmente activas en workers: {len(active_tasks)}")

    try:
        # Iterar sobre todos los jobs en Redis
        for key in r.scan_iter("job:*:folder"):
            try:
                if isinstance(key, bytes):
                    key = key.decode()

                job_id = key.split(":")[1]

                # 1. Ignorar jobs ya finalizados
                ready_flag = r.get(f"job:{job_id}:ready")
                if ready_flag and ready_flag.lower() in ("true", "1"):
                    logger.debug(f"Job {job_id} marcado como ready, ignorando")
                    skipped_count += 1
                    continue

                # 2. Obtener info mínima del job
                folder = r.get(f"job:{job_id}:folder")
                start_iso = r.get(f"job:{job_id}:start")
                end_iso=r.get(f"job:{job_id}:end")
                task_id = r.get(f"job:{job_id}:task_id")

                if not folder or not start_iso:
                    logger.warning(f"Job {job_id}: datos incompletos, ignorando")
                    skipped_count += 1
                    continue

                # 3. verificar que carpeta existe

                folder_path = get_folder_path_secure(folder)
                if not folder_path.exists():
                    logger.warning(f"Job {job_id}: carpeta {folder} no existe, marcando ready")
                    r.set(f"job:{job_id}:ready", "1")
                    skipped_count += 1
                    continue

                # 4. Decidir si relanzar
                should_relaunch = False
                reason = ""

                if not task_id:
                    # Caso A: No tiene task_id → definitivamente relanzar

                    should_relaunch = True
                    reason = "sin task_id"
                else:
                    # Caso B: Tiene task_id → verificar si la tarea existe y su estado
                    # Preguntar si el task_id está activo en workers
                    if task_id in active_tasks:
                        # la tarea esta corriendo en algún worker
                        logger.info(f"Job {job_id}: tarea realmente activa, no relanzar")
                        skipped_count += 1
                        continue
                    # Si NO está activa, verificar estado en backend
                    else:
                        try:
                            result = AsyncResult(task_id, app=process_job.app)
                            backend_state = result.state

                            logger.debug(
                                f"Job {job_id}: task_id {task_id} no activo en workers, estado backend={backend_state}")

                            # Verificar estados finales (no relanzar)
                            if backend_state == 'SUCCESS':
                                logger.info(f"Job {job_id}: tarea completada exitosamente, marcando ready")
                                r.set(f"job:{job_id}:ready", "1")
                                skipped_count += 1
                                continue

                            elif backend_state in ['FAILURE', 'REVOKED', 'REJECTED']:
                                logger.warning(
                                    f"Job {job_id}: tarea terminó con estado {backend_state}, marcando ready")
                                r.set(f"job:{job_id}:ready", "1")
                                skipped_count += 1
                                continue

                            elif backend_state in ['PENDING', 'STARTED']:
                                # Estados que indican tarea perdida/obsoleta
                                should_relaunch = True
                                reason = f"tarea perdida (estado backend={backend_state}, no activo en workers)"

                                # IMPORTANTE: Limpiar backend obsoleto antes de relanzar
                                try:
                                    result.forget()
                                    logger.debug(f"Backend de task_id {task_id} limpiado")
                                except Exception as e:
                                    logger.warning(f"No se pudo limpiar backend de {task_id}: {e}")

                            else:
                                # Estado desconocido → relanzar por seguridad
                                should_relaunch = True
                                reason = f"estado desconocido: {backend_state}"

                                # Limpiar backend
                                try:
                                    result.forget()
                                    logger.debug(f"Backend de task_id {task_id} limpiado")
                                except Exception as e:
                                    logger.warning(f"No se pudo limpiar backend de {task_id}: {e}")

                        except Exception as e:
                            # Error al consultar Celery → probablemente la tarea no existe
                            logger.warning(f"Job {job_id}: error consultando backend de task {task_id}: {e}",exc_info=True)
                            should_relaunch = True
                            reason = "error consultando backend (tarea probablemente no existe)"

                # 5. Relanzar si procede
                if should_relaunch:
                    logger.info(f"Job {job_id}: relanzando ({reason})")

                    new_task = app.send_task(
                        'tasks.process_job',  # Nombre completo de la tarea
                        args=[job_id, folder, start_iso,end_iso],
                        queue='pcaps'
                    )

                    # Actualizar task_id en Redis
                    r.set(f"job:{job_id}:task_id", new_task.id)
                    old_task_key = f"job:{job_id}:task.id"
                    if r.exists(old_task_key):
                        r.set(old_task_key, new_task.id)

                    logger.info(f"Job {job_id} relanzado con nuevo task_id {new_task.id}")
                    relaunched_count += 1

            except Exception as e:
                logger.error(f"✗ Error procesando job {job_id}: {e}", exc_info=True)
                error_count += 1

    except Exception as e:
        logger.error(f"✗ Error crítico en recuperacion de jobs: {e}", exc_info=True)

    logger.info("=" * 60)
    logger.info(f"Recuperacion completada:")
    logger.info(f"  - Jobs relanzados: {relaunched_count}")
    logger.info(f"  - Jobs ignorados: {skipped_count}")
    logger.info(f"  - Errores: {error_count}")
    logger.info("=" * 60)

def main(folder: str):
    """Procesa todos los archivos .pcap/.net en la carpeta especificada de forma standalone."""
    logger.info("Ejecución de procesado de ficheros desde MAIN, sin tasks de celery, modo standalone procesamiento secuencial")
    folder_path = get_folder_path_secure(folder)
    if not folder_path.exists() or not folder_path.is_dir():
        logger.error(f"La carpeta {folder} no existe o no es un directorio")
        raise ValueError(f"Carpeta {folder} inválida")

    output_csv = folder_path / "pcap_summary.csv"
    # Crear cabecera si el archivo CSV no existe
    if not output_csv.exists():
        with open(output_csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "src_ip", "dst_ip", "protocol", "info_type", "value"])

    # Buscar y procesar archivos
    files = find_capture_files(folder_path)
    if not files:
        logger.info(f"No se encontraron archivos .pcap o .net en {folder}")
        return

    for fpath in files:
        logger.info(f"Procesado secuencial fichero {fpath}")
        process_capture_fast(fpath, output_csv,pytime.time(), "11111")

def update_redis_state_to(new_state,job_id):
    current = r.get(f"job:{job_id}:job_state")
    if not current or current != config[new_state]:
        r.set(f"job:{job_id}:job_state", config[new_state])

def get_folder_path_secure(folder):
    """
    Devuelve el objeto ruta de un string ruta tanto para docker como para ejecución local
    """
    if config["TASKS_LOCAL"]:
        folder_param = folder
        subfolder_name = Path(folder_param).name
        folder_path = (LOCAL_CAP_ROOT / subfolder_name)
    else:
        folder_path = Path(folder)
    return folder_path

if __name__ == "__main__":
    #recover_active_jobs_logic()
    # Ruta de la carpeta con archivos .pcap (ajusta según tu caso)
    folder_to_process = "./pcaps/a"
    main(folder_to_process)