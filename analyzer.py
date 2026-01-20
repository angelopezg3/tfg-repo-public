"""
Project developed as part of the Trabajo de Fin de Grado (TFG)
Grado en Ingeniería Informática - UNIR

Author: angelopezg3
Year: 2026
License: MIT

Módulo para incluir el código de análisis de bajo nivel de los protocolos.
"""
from pathlib import Path

import pyshark
from device_detector import DeviceDetector
from utils import config, safe_snippet, logger, datetime
import re
import base64
import urllib.parse
from typing import List, Dict
from user_agents import parse
from ipaddress import IPv4Address, IPv6Address, ip_address

# -----------------------
# Helpers para detectar credenciales
# -----------------------
BASE64_RE = re.compile(rb'([A-Za-z0-9+/]{8,}={0,2})')
# tokens base64 largos. rb-> raw bytes
# [A-Za-z0-9+/]->letras mayusculas y minusculas, numeros, + y /
# {8,} -> al menos 8 caracteres seguidos
# ={0,2} -> opcionalmente 0,1 o 2 signos = (para el padding de relleno final)

# patrones seguros para user/pass (usar re.escape)
user_keys_list = config.get("USER_KEYS")
pass_keys_list = config.get("PASS_KEYS")

# crear una alternation segura: (?:username|user|...)
user_keys_pattern = r"(?:{})".format("|".join(re.escape(x) for x in user_keys_list))
pass_keys_pattern = r"(?:{})".format("|".join(re.escape(x) for x in pass_keys_list))

# compilar para rendimiento
USER_KEYS_RE = re.compile(user_keys_pattern, flags=re.I)
PASS_KEYS_RE = re.compile(pass_keys_pattern, flags=re.I)

# Convertir keywords a bytes (minúsculas) para comparar con raw.lower()
CRED_KEYWORDS = [kw.encode() for kw in config.get("CRED_KEYWORDS", [])]


def search_credentials(batch, raw, ts_packet, src, src_so, dst, dst_port, capture_path_str, packet_count, job_id):
    """
    Función para búsqueda de credenciales

    Args:
        batch: Lista para añadir la info obtenida
        raw: bytes del payload a analizar
        ts_packet: timestamp del frame en curso
        src: ip origen
        src_so: valor de TTL e inferencia de SO (para añadir contexto en la linea del csv)
        dst: ip destino
        dst_port: puerto destino
        capture_path_str: ruta del fichero en curso
        packet_count: número del frame en curso
        job_id: id del job actual

    Returns: lista con nueva entrada que contiene la info extraída.

    """

    creds = []
    creds = find_credentials_by_context(raw, src, dst, dst_port, capture_path_str, packet_count)
    file_name = Path(capture_path_str).name
    if len(raw) > 10:
        raw_lower = raw.lower()
        if any(k in raw_lower for k in CRED_KEYWORDS):
            creds.extend(find_credentials_in_payload(raw, src, dst, dst_port, capture_path_str, packet_count))

    for c in creds:
        # guardar usuario/contraseña en el batch; incluye nota y fragmento para contexto
        snippet = raw[:200]  # bytes de ejemplo para contexto (evita volcar todo)
        snippet_str = safe_snippet(snippet)
        ts_now = datetime.now().isoformat()
        line = [ts_now, file_name, ts_packet, src, src_so, dst, "CREDENTIAL", c.get("proto"), c.get("user"),
                c.get("pass"),
                c.get("note"), snippet_str]
        batch.append(line)
        logger.info(f"job:{job_id}:Contraseñas encontradas: {line}")
    return batch


def search_http_hosts(batch, raw, ts_packet, file_name, src, src_so, dst, job_id):
    """
    Busca cabeceras HTTP Host en un payload TCP y añade resultados al batch.

    Args:
        batch: Lista para añadir la info obtenida
        raw: bytes del payload a analizar
        ts_packet: timestamp del frame en curso
        file_name: nombre del fichero en curso
        src: ip origen
        src_so: valor de TTL e inferencia de SO (para añadir contexto en la linea del csv)
        dst: ip destino
        job_id: id del job en curso

    Returns: lista con nueva entrada que contiene la info extraída.

    """

    if len(raw) < 10:
        return batch

    # Solo buscar si parece tráfico HTTP
    if any(method in raw for method in (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"CONNECT ", b"HTTP/")):
        try:
            # Buscar cabecera Host: flexible (case-insensitive)
            m = re.search(rb"(?i)\bHost\s*:\s*([^\r\n]+)", raw)
            """Expresion regular
                - rb regexp sobre bytes
                - (?i) ignore case
                - \\b límite de palabra (evitaría X-Host por ejemplo)
                -Host: Busca literalmente la palabra "Host" en el string (con el ignore case anterior Host, host, HOST...)
                \\s*
                \\s significa cualquier carácter de espacio en blanco (espacio, tab, salto de línea…).
                * significa 0 o más repeticiones.
                - : caracter ":"
                ([^\r\n]+) Todo lo que hay después de Host: hasta un salto de linea (sin incluirlo, ^ negación)
                () grupo de captura: todo lo que coincida dentro se puede recuperar con m.group(1).
            """
            if m:
                host = m.group(1).strip().decode(errors="ignore")
                ts_now = datetime.now().isoformat()
                batch.append([ts_now, file_name, ts_packet, src, src_so, dst, src_so, "HTTP", "host", host])
        except Exception as e:
            logger.debug(f"job:{job_id}:Error al analizar Host en HTTP: {e}", exc_info=True)
    return batch


def try_b64_decode(token: bytes) -> bytes:
    """
    Decodificación base 64 de un conjunto de bytes.
    Args:
        token: entrada a decodificar

    Returns: los bytes decodificados
    """
    try:
        return base64.b64decode(token, validate=True)
    except Exception:
        # intentar padding o ignorar
        try:
            return base64.b64decode(token + b'=' * ((4 - len(token) % 4) % 4))
        except Exception:
            return b''


def extract_basic_auth(payload_str: str) -> List[Dict]:
    """
    Extrae credenciales de peticiones HTTP Basic Auth.
    En basic auth el formato es así: Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
    siendo QWxhZGRpbjpvcGVuIHNlc2FtZQ== la codificación en base64 de usuario:password
    Args:
        payload_str: el string del payload a analizar

    Returns: lista con nueva entrada que contiene la info extraída.
    """
    findings = []
    m = re.search(r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', payload_str, flags=re.I)
    """Expresion regular
    -Authorization: Busca literalmente la palabra "Authorization:" en el string.
    No hace distinción entre mayúsculas y minúsculas porque se usa flags=re.I (case-insensitive).
    \\s*
    \\s significa cualquier carácter de espacio en blanco (espacio, tab, salto de línea…).
    * significa 0 o más repeticiones.
    \\s+
    espacio en blanco una o más repeticiones
    ([A-Za-z0-9+/=]+)
    () grupo de captura: todo lo que coincida dentro se puede recuperar con m.group(1).
    [A-Za-z0-9+/=] = cualquier carácter alfanumérico (A-Z, a-z, 0-9) o +, / o =
    Estos son los caracteres válidos en Base64.
    """
    if m:
        b64 = m.group(1).encode()
        raw = try_b64_decode(b64)
        if raw:
            try:
                userpass = raw.decode(errors="ignore")
                if ':' in userpass:
                    user, pwd = userpass.split(':', 1)
                    findings.append({"proto": "HTTP-Basic", "user": user, "pass": pwd, "note": "Authorization: Basic"})
            except Exception:
                pass
    return findings


def extract_url_credentials(payload_str: str) -> List[Dict]:
    """
    Detecta credenciales en urls del tipo http://user:pass@host/...
    Expresión regular:
        buscar ://
        () grupo 1. [^:@\\s/]+ caracteres que no sean : @ espacio en blanco o / una o mas veces (+)
        () grupo 2. [^@/\\s]+ caracteres que no sean @ / o espacio en blanco
        @ para terminar

    Returns: lista con nueva entrada que contiene la info extraída.
    """
    findings = []
    for m in re.finditer(r'://([^:@\s/]+):([^@/\s]+)@', payload_str):
        user = m.group(1)
        pwd = m.group(2)
        findings.append({"proto": "URL-cred", "user": user, "pass": pwd, "note": "credenciales en URL"})
    return findings


def extract_form_credentials(payload_str: str) -> List[Dict]:
    """
    Detecta credenciales enviadas vía formularios HTTP:
      - application/x-www-form-urlencoded (user=...&password=...)

    Usa USER_KEYS_RE y PASS_KEYS_RE compiladas desde config.

    Args:
        payload_str: string del payload a analizar

    Returns: lista con nueva entrada que contiene la info extraída.

    """
    findings = []
    if not payload_str:
        return findings

    # --- Normalización y decodificación básica ---
    # Algunos payloads pueden venir con encoding tipo URL ejemplo unquote_plus('/El+Ni%C3%B1o/') devuelve '/El Niño/'.
    decoded = urllib.parse.unquote_plus(payload_str)
    decoded = decoded.strip()

    # Form-urlencoded o querystring simple
    # Buscar pares tipo key=value (ignorando espacios o separadores & ?)
    pairs = re.findall(r'([^&=\s]+)=([^&\s]+)', decoded)
    """
    Expresión regular:
    ()=() dos grupos separados por un igual
    Grupo 1. [^&=\\s]+ Caracteres que no sean & = o espacio una o mas veces
    Grupo 2. [^&\\s]+ Caracteres que no sean & o espacio una o mas veces

    por ejemplo "login=admin&pwd=p@ss&debug=true" obtendríamos 3 pares: [('login', 'admin'), ('pwd', 'p@ss'), ('debug', 'true')]
    """
    user_val, pass_val = None, None

    # de todos los pares extraídos nos quedamos con aquellos en los que la clave sea una de las listadas en
    # USER_KEYS o PASS_KEYS (de fichero de config)
    for k, v in pairs:
        key = urllib.parse.unquote_plus(k).lower()
        val = urllib.parse.unquote_plus(v)
        if user_val is None and USER_KEYS_RE.search(key):
            user_val = val
        if pass_val is None and PASS_KEYS_RE.search(key):
            pass_val = val
        if user_val and pass_val:
            findings.append({
                "proto": "HTTP-Form",
                "user": user_val,
                "pass": pass_val,
                "note": "form"
            })
            break

    # Evitar duplicados
    unique = []
    seen = set()
    for f in findings:
        key = (f["proto"], f["user"], f["pass"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def extract_ftp_pop(payload_str: str, dst_port, capture_path_str, packet_count) -> List[Dict]:
    """
    Extrae credenciales de peticiones FTP y POP. En estos protocolos el valor del usuario va desupes de USER y
    la contraseña después de PASS
    Args:
        payload_str: string con el payload a analizar
        dst_port: puerto destino
        capture_path_str: ruta del fichero en curso
        packet_count: frame en curso

    Returns: lista con nueva entrada que contiene la info extraída.

    """
    findings = []
    request_user_re = re.search(r'(?m)^\s*USER\s+([^\r\n]+)', payload_str)
    request_pass_re = re.search(r'(?m)^\s*PASS\s+([^\r\n]+)', payload_str)
    """
        Expresiones regulares:
        (?m) habilitar modo multilinea (por si hubiera \n)
        ^\\s*':
            ^ inicio de linea
            s* 0 o n espacios en blanco o tabulaciones
        USER: literal
        \\s+ Uno o mas espacios en blanco o tabulaciones
         ([^\r\n]+) : Captura todo lo que no sea \r\n
            () Grupo de captura
            [^ ] Conjunto negado
                \r\n retorno carro y salto de linea

        Ejemplo:
            Entrada:    220 FTP Service Ready
                        USER anonymous
                        PASS guest@
                        SYST
            Salida: anonymous 

    """
    request_user = request_user_re.group(1).strip() if request_user_re else None
    request_pass = request_pass_re.group(1).strip() if request_pass_re else None

    if request_user is not None or request_pass is not None:
        if dst_port == 22:
            # FTP: USER <user>\r\n PASS <pass>\r\n
            if request_user and request_pass:
                findings.append({"proto": "FTP", "user": request_user, "pass": request_pass, "note": "FTP USER/PASS"})
            elif request_user:
                findings.append({"proto": "FTP", "user": request_user, "note": "FTP USER"})
            elif request_pass:
                findings.append({"proto": "FTP", "pass": request_pass, "note": "FTP PASS"})
        elif dst_port == 110:
            # POP3 plain USER/PASS
            if request_user and request_pass:
                findings.append({"proto": "POP3", "user": request_user, "pass": request_pass, "note": "USER/PASS"})
            elif request_user:
                findings.append({"proto": "POP3", "user": request_user, "note": "FTP USER"})
            elif request_pass:
                findings.append({"proto": "POP3", "pass": request_pass, "note": "FTP PASS"})
        else:
            # protocolo no identificado por puerto, analizamos con pyshark
            extra_info = pyshark_packet_analysis(capture_path_str, packet_count)
            if request_user and request_pass:
                findings.append({"proto": extra_info["proto"], "user": request_user, "pass": request_pass})
            elif request_user:
                findings.append({"proto": extra_info["proto"], "user": request_user})
            elif request_pass:
                findings.append({"proto": extra_info["proto"], "pass": request_pass})

    return findings


def extract_telnet_auth(payload_str: str, src, dst, packet_count, capture_path_str) -> List[Dict]:
    """
        Extracción de usuario y contraseña de TELNET.
        Si llegamos aquí es porque el puerto de destino es el 23, el cliente manda datos al servidor.

        Para obtener usuario miramos el paquete siguiente a aquel en el que va login:
        Para obtener el password miramos el paquete siguiente a aquel en el que va Password:
        Packet N (server->client): login:
        Packet N+1 (client->server): testuser\r\n
        Packet N+2 (server->client): Password:
        Packet N+3 (client->server): 1234\r\n

    Args:
        payload_str: string del payload a analizar.
        src: ip origen
        dst: ip destino
        packet_count: frame en curso
        capture_path_str: ruta del fichero en curso

    Returns: lista con usuarios y contraseñas

    """

    findings = []
    # para buscar el usuario tenemos que buscar login en los n paquetes anteriores que vengan del servidor
    # si paquete telnet anterior viene de antigua ip dst y contiene login entonces el contenido de este es el login
    # para buscar el password tenemos que buscar password en los n paquetes anteriores que vengan del servidor
    # si paquete telnet anterior viene de antigua ip dst y contiene password entonces el contenido de este es el password
    for i in range(1, config["MAX_PACKETS_BACK"]):
        previous_packet_num = packet_count - i
        extra_info = pyshark_packet_analysis(capture_path_str, previous_packet_num)
        # Si el destino del paquete telnet anterior es el origen del paquete actual...
        if "telnet_dest" in extra_info:
            if extra_info["telnet_dest"] == src:
                # y en el paquete anterior venía login o password...
                m_login = re.search(r'login[: ]\s*([^\r\n]+)', extra_info["telnet_payload"], flags=re.I)
                if m_login:
                    findings.append(
                        {"proto": "telnet-like", "user": payload_str.rstrip(),
                         "note": "interactive login prompts"})
                    break
                m_pass = re.search(r'password[: ]\s*([^\r\n]+)', extra_info["telnet_payload"], flags=re.I)
                if m_pass:
                    findings.append(
                        {"proto": "telnet-like", "password": payload_str.rstrip(),
                         "note": "interactive password prompts"})
                    break
            else:
                break
    return findings


def extract_any_base64_pair(payload_bytes: bytes) -> List[Dict]:
    """
    Busca cadenas base64 que, al decodificar, contengan separator ":" o \x00

    Args:
        payload_bytes: payload en bytes a analizar

    Returns: lista con las cadenas encontradas

    """
    #
    findings = []
    for m in BASE64_RE.finditer(payload_bytes):
        token = m.group(1)
        decoded = try_b64_decode(token)
        if decoded:
            if b':' in decoded:
                try:
                    u, p = decoded.split(b':', 1)
                    u = u.decode(errors="ignore");
                    p = p.decode(errors="ignore")
                    if u and p:
                        findings.append({"proto": "b64-colon", "user": u, "pass": p, "note": "base64 with colon"})
                except Exception:
                    pass
            if b'\x00' in decoded:
                parts = decoded.split(b'\x00')
                if len(parts) >= 3:
                    try:
                        # parts[0] suele contenener "AUTH" o "LOGIN"
                        u = parts[1].decode(errors="ignore");
                        p = parts[2].decode(errors="ignore")
                        findings.append({"proto": "b64-nul", "user": u, "pass": p, "note": "base64 with NULs"})
                    except Exception:
                        pass
    return findings


def find_credentials_by_context(payload: bytes, src, dst, dst_port, capture_path_str, packet_count) -> List[Dict]:
    """
    Busca credenciales que no llevan identificación de user o password en el propio paquete sino en el anterior
        TELNET ejemplo:
            Packet N (server->client): login:
            Packet N+1 (client->server): testuser\r\n  Directamente valor del usuario
            Packet N+2 (server->client): Password:
            Packet N+3 (client->server): 1234\r\n      Directamente valor del password

    Args:
        payload: contenido a analizar
        src:  ip de origen
        dst:  ip de destino
        dst_port: puerto de destino
        capture_path_str: ruta del fichero en curso
        packet_count: frame number del paquete en curso

    Returns: lista con los usuarios y contraseñas

    """

    findings = []
    if not payload:
        return findings
    if dst_port == 23:
        # tratar payload como string para búsquedas simples
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
        except Exception:
            payload_str = str(payload)

        # telnet
        findings.extend(extract_telnet_auth(payload_str, src, dst, packet_count, capture_path_str))
    return findings


def find_credentials_in_payload(payload: bytes, src, dst, dst_port, capture_path_str, packet_count) -> List[Dict]:
    """
    Busca credenciales (usuarios y contraseñas) en el contenido del paquete.
    Busca varios tipos:
    - HTTP Basic Auth header
    - Credenciales en URL
    - Credenciales en el contenido de formularios
    - Credenciales en FTP/POP
    - Credenciales en cualquier cadena en base64

    Args:
        payload: payload a analizar
        src: ip origen
        dst: ip destino
        dst_port: puerto destino
        capture_path_str: ruta del fichero que estamos analizando
        packet_count: frame en curso

    Returns: Devuelve lista de dicts con campos: proto,user,pass,note

    """

    findings = []
    if not payload:
        return findings

    # tratar payload como string para búsquedas simples
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
    except Exception:
        payload_str = str(payload)

    # 1) HTTP Basic Auth
    findings.extend(extract_basic_auth(payload_str))

    # 2) credenciales en url
    findings.extend(extract_url_credentials(payload_str))

    # 3) form-urlencoded / multipart
    findings.extend(extract_form_credentials(payload_str))

    # 4) FTP/POP
    findings.extend(extract_ftp_pop(payload_str, dst_port, capture_path_str, packet_count))

    # 5) base64 cadenas que decodificadas sean user:pass o \x00user\x00pass
    findings.extend(extract_any_base64_pair(payload))

    # deduplicate by (proto,user,pass)
    uniq = []
    seen = set()
    for f in findings:
        key = (f.get("proto"), f.get("user"), f.get("pass"))
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq


def return_ttl_so_name(ttl_number):
    """
    Devuelve inferencia de sistema operativo en función del TTL del paquete (capa de red, protocolo IP)
    Args:
        ttl_number: valor del ttl

    Returns: cadena con SistemaOperativoValor ejemplo Linux64
    """
    if 0 <= ttl_number <= 64:
        return f"Linux{ttl_number}"
    elif 65 <= ttl_number <= 128:
        return f"Windows{ttl_number}"
    else:
        return f"SO Unknown{ttl_number}"


def parse_user_agent(ua_string: str, android_models) -> str:
    """
    Devuelve una descripción legible del User-Agent detectado:
    Ejemplo: "Samsung Galaxy A51 (Android 11, Chrome 118.0.0.0)"

    Args:
        ua_string: string del user agent tal cual va
        android_models: diccionario con la info de dispositivos Android

    Returns: String con el user agent parseado/enriquecido

    """

    if not ua_string:
        return "Desconocido"

    try:
        dd = DeviceDetector(ua_string).parse()

        client = dd.client_name() or "Desconocido"
        client_ver = dd.client_version() or ""
        os = dd.os_name() or "Desconocido"
        os_ver = dd.os_version() or ""
        device = dd.device_type() or "desconocido"
        brand = dd.device_brand() or ""
        model = dd.device_model() or ""

        # Intentar traducir modelo Android técnico
        model_up = model.upper().strip()
        if model_up in android_models:
            model = android_models[model_up]

        # Construir descripción legible
        partes = []
        if brand or model:
            partes.append(f"{brand} {model}".strip())
        if os != "Desconocido":
            partes.append(f"{os} {os_ver}".strip())
        if client != "Desconocido":
            partes.append(f"{client} {client_ver}".strip())

        texto = ", ".join(partes)
        return texto if texto else "No identificado"

    except Exception as e:
        return f"No identificado ({type(e).__name__})"


def search_user_agent(batch, raw, ts_packet, file_name, src, src_so, dst, android_models, job_id):
    """
    Busca cabeceras HTTP User-Agent en un payload TCP y añade resultados al batch (aplica enriquecimiento de
    user agents con cache de dispositivos android y otras librerias).

    Args:
        batch: Lista para añadir la info obtenida
        raw: payload en bytes
        ts_packet: timestamp del paquete
        file_name: nombre del fichero actual
        src: ip origen
        src_so: valor de TTL e inferencia de SO (para añadir contexto en la linea del csv)
        dst: ip destino
        android_models: diccionario con la info de los modelos de dispositivos Android
        job_id: id del job actual

    Returns: lista batch con nueva entrada con la info obtenida

    """

    ua_parsed = ""
    ua_parsed_string = ""
    ua_parsed_inspect = ""

    if len(raw) < 20:
        return batch

    # Solo buscar si parece tráfico HTTP
    if any(method in raw for method in (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"CONNECT ", b"HTTP/")):
        try:
            # Buscar cabecera User-Agent flexible (case-insensitive)
            m = re.search(rb"(?i)\bUser-Agent\s*:\s*([^\r\n]+)", raw)
            if m:
                ua = m.group(1).strip().decode(errors="ignore")

                # Intentar parsear con DeviceDetector (más completo que ua-parser)
                try:
                    # dd = DeviceDetector(ua).parse()
                    # ua_parsed = parse(ua)
                    # ua_parsed_string = f"Aplicacion: {ua_parsed.browser.family} {ua_parsed.browser.version_string}, SO: {ua_parsed.os.family} {ua_parsed.os.version_string}, Dispositivo: {ua_parsed.device.family}"
                    ua_parsed_inspect = parse_user_agent(ua, android_models)
                except Exception:
                    ua_parsed_string = "Parse error"
                ts_now = datetime.now().isoformat()
                batch.append([
                    ts_now, file_name, ts_packet, src, src_so, dst,
                    "HTTP", "user_agent", ua, ua_parsed_inspect
                ])

        except Exception as e:
            logger.debug(f"job:{job_id}:Error al analizar User-Agent: {e}", exc_info=True)

    return batch


def pyshark_packet_analysis(pcap_path: str, frame_number: int):
    """
    Analiza solo un paquete (por número de frame) con PyShark.
    Devuelve protocolo de aplicación o información extendida.
    Args:
        pcap_path: ruta del fichero pcap
        frame_number: frame en curso

    Returns: diccionario con info sobre el frame (protocolo y otros datos según el protocolo)

    """
    try:
        # logger.debug(f"Analizando frame{frame_number} con pyshark")
        cap = pyshark.FileCapture(
            pcap_path,
            display_filter=f"frame.number == {frame_number}",
            keep_packets=False,
            custom_parameters=[
                '-o', 'tcp.desegment_tcp_streams:TRUE',
                '-o', 'tls.desegment_ssl_records:TRUE'
            ]
        )
        pkt = None
        info = None
        for pkt in cap:

            info = {'proto': pkt.highest_layer}
            if hasattr(pkt, 'ftp'):
                info.update({
                    'proto': 'FTP',
                    'command': getattr(pkt.ftp, 'request_command', None),
                    'arg': getattr(pkt.ftp, 'request_arg', None)
                })
            elif hasattr(pkt, 'telnet'):
                info.update({
                    'proto': 'TELNET',
                    'telnet_dest': getattr(pkt.ip, 'dst', None),
                    'telnet_payload': getattr(pkt.telnet, 'data', None),
                    'note': 'Telnet data or negotiation'
                })

                """    
                elif hasattr(pkt, 'http'):
                    info.update({
                        'proto': 'HTTP',
                        'host': getattr(pkt.http, 'host', None),
                        'uri': getattr(pkt.http, 'request_uri', None)
                    })

                elif hasattr(pkt, 'tls'):
                    info.update({
                        'proto': 'TLS',
                        'sni': getattr(pkt.tls, 'handshake_extensions_server_name', None)
                    })
                """
            cap.close()
            break
        return info
    except Exception as e:
        print(f"Error analizando paquete {frame_number}: {e}")
        return {}


def build_frame_sni_map(pcap_path: str, job_id):
    """
    Devuelve un diccionario {frame_number: SNI} para todos los ClientHello TLS del PCAP.
    Maneja tanto paquetes fragmentados como no fragmentados.

    Args:
        pcap_path: fichero pcap a analizar
        job_id: id del job en curso para log

    Returns: diccionario {frame_number: SNI}
    """

    frame_sni_map = {}
    logger.debug(f"job:{job_id}:Cargando PCAP completo: {pcap_path} para análisis sni")

    with pyshark.FileCapture(
            pcap_path,
            display_filter="tls.handshake.type==1",  # solo ClientHello
            keep_packets=True,
            override_prefs={
                "tcp.desegment_tcp_streams": "TRUE",
                "tls.desegment_ssl_records": "TRUE",
                "tls.desegment_ssl_application_data": "TRUE",
                "tcp.analyze_sequence_numbers": "TRUE"
            }
    ) as cap:

        cap.load_packets()  # carga todos de una vez

        for pkt in cap:
            frame_number = int(pkt.number)
            sni = None

            if hasattr(pkt, 'tls'):
                # Paquete completo
                for field in [
                    "handshake_extensions_server_name",
                    "handshake_extension_server_name",
                    "extension_server_name",
                    "server_name",
                    "handshake.extensions_server_name",
                    "handshake.extensions_server_name_list",
                ]:
                    if field in pkt.tls.field_names:
                        sni = getattr(pkt.tls, field, None)
                        if sni:
                            break

            if sni:
                frame_sni_map[frame_number] = sni

    return frame_sni_map


def is_stun_packet(payload: bytes) -> bool:
    """
    Detecta si un payload UDP/TCP corresponde a un mensaje STUN (en función de los bytes 4-7)

    Args:
        payload: payload a analizar

    Returns: True o False si es STUN
    """

    if len(payload) < 20:  # mínimo tamaño header STUN
        return False
    # Magic cookie bytes 4-7 (big endian)
    magic_cookie = payload[4:8]
    if magic_cookie == b'\x21\x12\xa4\x42':
        return True
    return False


def search_stun_info(batch, raw, ts_packet, file_name, src, src_so, dst, dst_port):
    """
    Código para la obtención de ip y puerto de origen y destino de las llamadas STUN. Procesamos a partir de los
    bytes del contenido de la capa de aplicación a partir de los message_types. Tenemos que buscar los:
        Binding Request (message_type 0x0001)
        Allocate Success Response (message_type 0x0103

    Args:
        batch: Lista para añadir la info obtenida
        raw: payload en bytes para analziar
        ts_packet: timestamp del paquete
        file_name: nombre del fichero que analizamos
        src: ip origen
        src_so: valor de TTL e inferencia de SO (para añadir contexto en la linea del csv)
        dst: ip destino
        dst_port: puerto de destino

    Returns: Lista con nueva entrada con la info obtenida

    """
    if is_stun_packet(raw):
        # logger.debug(f"job:{job_id}:detectado paquete stun en UDP: paquete {packet_count}")

        # Message Type (2 bytes, big endian)
        msg_type = int.from_bytes(raw[0:2], byteorder='big')

        if msg_type == 0x0001:
            # Binding Request
            if not ip_address(dst).is_private:
                ts_now = datetime.now().isoformat()
                batch.append(
                    [ts_now, file_name, ts_packet, src, src_so, dst, "STUN CALL", "to ip", dst, "to port", dst_port])

            return batch
        elif msg_type == 0x103:
            # Allocate Success Response
            # magic cookie para XOR
            magic_cookie = raw[4:8]

            # atributos empiezan en byte 20
            offset = 20
            while offset + 4 <= len(raw):
                attr_type = int.from_bytes(raw[offset:offset + 2], 'big')
                attr_len = int.from_bytes(raw[offset + 2:offset + 4], 'big')
                attr_value = raw[offset + 4:offset + 4 + attr_len]

                if attr_type == 0x0020:  # Atributo XOR-MAPPED-ADDRESS
                    # Formato:
                    # 1 byte family, 2 bytes port (XOR con magic cookie)
                    # 4 bytes IPv4 address (XOR con magic cookie) o 16 bytes IPv6 (XOR con magic cookie + transaction ID)
                    family = attr_value[1]
                    xport = int.from_bytes(attr_value[2:4], 'big') ^ (
                            magic_cookie[0] << 8 | magic_cookie[1])
                    if family == 0x01:  # IPv4
                        xip = IPv4Address(
                            int.from_bytes(attr_value[4:8], 'big') ^ int.from_bytes(
                                magic_cookie, 'big'))
                    elif family == 0x02:  # IPv6
                        # para IPv6 se XOR con magic cookie + transaction ID (bytes 4:20)
                        xor_bytes = magic_cookie + raw[8:20]
                        xip = IPv6Address(
                            int.from_bytes(attr_value[4:20], 'big') ^ int.from_bytes(xor_bytes,
                                                                                     'big'))
                    else:
                        return batch
                    ts_now = datetime.now().isoformat()
                    batch.append(
                        [ts_now, file_name, ts_packet, src, src_so, dst, "STUN CALL", "from ip", xip, "from port",
                         xport])

                # pasar al siguiente atributo (alineado a 4 bytes)
                offset += 4 + ((attr_len + 3) // 4) * 4
            return batch

    return batch


if __name__ == "__main__":

    ejemplos = [
        "Mozilla/5.0 (Linux; Android 11; SM-A515F) AppleWebKit/537.36 Chrome/118.0.5993.117 Mobile Safari/537.36",
        "WhatsApp/2.23.11.76 A",
        "curl/7.68.0",
        "Mozilla/5.0 (Linux; Android 13; M2007J3SY) AppleWebKit/537.36 Chrome/117.0.0.0 Mobile Safari/537.36",
    ]

    for ua in ejemplos:
        print(f"\nUA: {ua}")
        print(" →", parse_user_agent(ua))
