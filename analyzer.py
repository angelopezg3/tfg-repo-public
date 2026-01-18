"""
Project developed as part of the Trabajo de Fin de Grado (TFG)
Grado en Ingeniería Informática - UNIR

Author: angelopezg3
Year: 2026
License: MIT
"""


import pyshark
from device_detector import DeviceDetector
from utils import config,safe_snippet,logger,datetime
import re
import base64
import urllib.parse
from typing import List, Dict
from user_agents import parse
from ipaddress import IPv4Address,IPv6Address,ip_address


# -----------------------
# Helpers para detectar credenciales
# -----------------------
BASE64_RE = re.compile(rb'([A-Za-z0-9+/]{8,}={0,2})')  # tokens base64 largos plausibles
# construir patrones seguros para user/pass (usar re.escape)
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

def search_credentials(batch, raw, ts_packet,file_name, src,src_so, dst, dst_port, capture_path_str,packet_count,job_id):
    """
        Filtro de longitud del raw no aplica a telnet porque no envía comando sino directamente el usuario y contraseña
    """
    creds=[]
    creds= find_credentials_by_context(raw,src, dst, dst_port,capture_path_str,packet_count)

    if len(raw) > 10:
        raw_lower = raw.lower()
        if any(k in raw_lower for k in CRED_KEYWORDS):
            creds.extend(find_credentials_in_payload(raw,src, dst, dst_port,capture_path_str,packet_count))

    for c in creds:
        # guardar usuario/contraseña en el batch; incluye nota y fragmento para contexto
        snippet = raw[:200]  # bytes de ejemplo para contexto (evita volcar todo)
        snippet_str = safe_snippet(snippet)
        ts_now=  datetime.now().isoformat()
        line=[ts_now,file_name, ts_packet, src, src_so, dst, "CREDENTIAL", c.get("proto"), c.get("user"), c.get("pass"),
                      c.get("note"), snippet_str]
        batch.append(line)
        logger.info(f"job:{job_id}:Contraseñas encontradas: {line}")
    return batch


def search_http_hosts(batch, raw, ts_packet,file_name, src, src_so, dst, job_id):
    """
    Busca cabeceras HTTP Host en un payload TCP y añade resultados al batch.
    """
    if len(raw) < 10:
        return batch

    # Solo buscar si parece tráfico HTTP
    if any(method in raw for method in (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"CONNECT ", b"HTTP/")):
        try:
            # Buscar cabecera Host: flexible (case-insensitive)
            m = re.search(rb"(?i)\bHost\s*:\s*([^\r\n]+)", raw)
            if m:
                host = m.group(1).strip().decode(errors="ignore")
                ts_now = datetime.now().isoformat()
                batch.append([ts_now,file_name,ts_packet, src, src_so, dst, src_so, "HTTP", "host", host])
        except Exception as e:
            logger.debug(f"job:{job_id}:Error al analizar Host en HTTP: {e}",exc_info=True)
    return batch

def try_b64_decode(token: bytes) -> bytes:
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
    En basic auth el formato es así: Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
    siendo QWxhZGRpbjpvcGVuIHNlc2FtZQ== la codificación en base64 de usuario:password
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
                    findings.append({"proto":"HTTP-Basic", "user": user, "pass": pwd, "note":"Authorization: Basic"})
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
    """
    findings = []
    for m in re.finditer(r'://([^:@\s/]+):([^@/\s]+)@', payload_str):
        user = m.group(1)
        pwd = m.group(2)
        findings.append({"proto":"URL-cred", "user": user, "pass": pwd, "note":"credenciales en URL"})
    return findings

def extract_form_credentials(payload_str: str) -> List[Dict]:
    """
    Detecta credenciales enviadas vía formularios HTTP:
      - application/x-www-form-urlencoded (user=...&password=...)
      - multipart/form-data (heurística)
    Usa USER_KEYS_RE y PASS_KEYS_RE compiladas desde config.
    """
    findings = []
    if not payload_str:
        return findings

    # --- Normalización y decodificación básica ---
    # Algunos payloads pueden venir con encoding tipo URL ejemplo unquote_plus('/El+Ni%C3%B1o/') devuelve '/El Niño/'.
    decoded = urllib.parse.unquote_plus(payload_str)
    decoded = decoded.strip()

    # ==================================================
    # 1) Form-urlencoded o querystring simple
    # ==================================================
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

    # ==================================================
    # 3) Evitar duplicados
    # ==================================================
    unique = []
    seen = set()
    for f in findings:
        key = (f["proto"], f["user"], f["pass"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def extract_imap_smtp(payload_str: str) -> List[Dict]:
    findings = []
    # SMTP AUTH LOGIN : typically sequence AUTH LOGIN <b64_user> <b64_pass>
    if 'AUTH LOGIN' in payload_str.upper():
        b64s = re.findall(r'([A-Za-z0-9+/]{8,}={0,2})', payload_str)
        if len(b64s) >= 2:
            u = try_b64_decode(b64s[0]).decode(errors="ignore")
            p = try_b64_decode(b64s[1]).decode(errors="ignore")
            if u and p:
                findings.append({"proto":"SMTP-AUTH", "user": u, "pass": p, "note":"AUTH LOGIN"})
    # AUTH PLAIN: base64 of \x00user\x00pass
    m = re.search(r'AUTH\s+PLAIN\s+([A-Za-z0-9+/=]+)', payload_str, flags=re.I)
    if m:
        raw = try_b64_decode(m.group(1).encode())
        if raw:
            parts = raw.split(b'\x00')
            if len(parts) >= 3:
                user = parts[1].decode(errors="ignore")
                pwd = parts[2].decode(errors="ignore")
                findings.append({"proto":"SMTP/POP/IMAP-AUTH-PLAIN", "user": user, "pass": pwd, "note":"AUTH PLAIN"})
    return findings


def extract_ftp_pop(payload_str: str,dst_port,capture_path_str,packet_count) -> List[Dict]:
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
    request_user=request_user_re.group(1).strip() if request_user_re else None
    request_pass = request_pass_re.group(1).strip() if request_pass_re else None

    if request_user is not None or request_pass is not None:
        if dst_port==22:
            # FTP: USER <user>\r\n PASS <pass>\r\n
            if request_user and request_pass:
                findings.append({"proto":"FTP", "user": request_user, "pass": request_pass, "note":"FTP USER/PASS"})
            elif request_user:
                findings.append({"proto": "FTP", "user": request_user,"note": "FTP USER"})
            elif request_pass:
                findings.append({"proto": "FTP", "pass": request_pass, "note": "FTP PASS"})
        elif dst_port==110:
            # POP3 plain USER/PASS
            if request_user and request_pass:
                findings.append({"proto":"POP3", "user": request_user, "pass": request_pass, "note":"USER/PASS"})
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
                findings.append({"proto": extra_info["proto"],"pass": request_pass})

    return findings

def extract_telnet_auth(payload_str: str, src, dst, packet_count, capture_path_str) -> List[Dict]:
    """
    Si llegamos aquí es porque el puerto de destino es el 23, el cliente manda datos al servidor.

        Packet N (server->client): login:
        Packet N+1 (client->server): testuser\r\n
        Packet N+2 (server->client): Password:
        Packet N+3 (client->server): 1234\r\n

    """
    findings = []
    # para buscar el usuario tenemos que buscar login en los n paquetes anteriores que vengan del servidor
    # si paquete telnet anterior viene de antigua ip dst y contiene login entonces el contenido de este es el login
    # para buscar el password tenemos que buscar password en los n paquetes anteriores que vengan del servidor
    # si paquete telnet anterior viene de antigua ip dst y contiene password entonces el contenido de este es el password
    for i in range(1,config["MAX_PACKETS_BACK"]):
        previous_packet_num=packet_count-i
        extra_info= pyshark_packet_analysis(capture_path_str,previous_packet_num)
        # Si el destino del paquete telnet anterior es el origen del paquete actual...
        if "telnet_dest" in extra_info:
            if extra_info["telnet_dest"]==src:
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
    # buscar pares base64 que, al decodificar, contengan separator : o \x00
    findings = []
    for m in BASE64_RE.finditer(payload_bytes):
        token = m.group(1)
        decoded = try_b64_decode(token)
        if decoded:
            if b':' in decoded:
                try:
                    u,p = decoded.split(b':',1)
                    u = u.decode(errors="ignore"); p = p.decode(errors="ignore")
                    if u and p:
                        findings.append({"proto":"b64-colon", "user":u, "pass":p, "note":"base64 with colon"})
                except Exception:
                    pass
            if b'\x00' in decoded:
                parts = decoded.split(b'\x00')
                if len(parts) >= 3:
                    try:
                        u = parts[1].decode(errors="ignore"); p = parts[2].decode(errors="ignore")
                        findings.append({"proto":"b64-nul", "user":u, "pass":p, "note":"base64 with NULs"})
                    except Exception:
                        pass
    return findings

def find_credentials_by_context(payload: bytes,src, dst, dst_port,capture_path_str,packet_count) -> List[Dict]:
    """
        Busca credenciales que no llevan identificación de user o password en el propio paquete sino en el anterior
        TELNET ejemplo:
            Packet N (server->client): login:
            Packet N+1 (client->server): testuser\r\n  Directamente valor del usuario
            Packet N+2 (server->client): Password:
            Packet N+3 (client->server): 1234\r\n      Directamente valor del password

    """
    findings = []
    if not payload:
        return findings
    if dst_port==23:
        # tratar payload como string para búsquedas simples
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
        except Exception:
            payload_str = str(payload)

        # telnet
        findings.extend(extract_telnet_auth(payload_str, src, dst, packet_count, capture_path_str))
    return findings

def find_credentials_in_payload(payload: bytes,src, dst, dst_port,capture_path_str,packet_count) -> List[Dict]:
    """
    Devuelve lista de dicts con campos: proto,user,pass,note
    """
    findings = []
    if not payload:
        return findings

    # tratar payload como string para búsquedas simples
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
    except Exception:
        payload_str = str(payload)

    # 1) HTTP Basic Auth header
    findings.extend(extract_basic_auth(payload_str))

    # 2) credentials in URL
    findings.extend(extract_url_credentials(payload_str))

    # 3) form-urlencoded / multipart
    findings.extend(extract_form_credentials(payload_str))

    # 4) FTP/POP
    findings.extend(extract_ftp_pop(payload_str,dst_port,capture_path_str,packet_count))

    # 4) IMAP/SMTP TODO MONTAR SERVERS DE PRUEBA E INTENTAR CAPTURAR CONTENIDO
    #findings.extend(extract_imap_smtp(payload_str))

    # 6) any base64 pairs that decode to user:pass or \x00user\x00pass
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

def search_user_agent(batch, raw, ts_packet,file_name, src,src_so, dst, android_models,job_id):
    """
    Busca cabeceras HTTP User-Agent en un payload TCP y añade resultados al batch.
    """
    ua_parsed=""
    ua_parsed_string=""
    ua_parsed_inspect=""

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
                    #dd = DeviceDetector(ua).parse()
                    #ua_parsed = parse(ua)
                    #ua_parsed_string = f"Aplicacion: {ua_parsed.browser.family} {ua_parsed.browser.version_string}, SO: {ua_parsed.os.family} {ua_parsed.os.version_string}, Dispositivo: {ua_parsed.device.family}"
                    ua_parsed_inspect = parse_user_agent(ua, android_models)
                except Exception:
                    ua_parsed_string = "Parse error"
                ts_now = datetime.now().isoformat()
                batch.append([
                    ts_now, file_name, ts_packet, src,src_so, dst,
                    "HTTP", "user_agent", ua, ua_parsed_inspect
                ])

        except Exception as e:
            logger.debug(f"job:{job_id}:Error al analizar User-Agent: {e}",exc_info=True)

    return batch

def search_sip_info(batch, raw, ts, src, dst, ttl_number, android_models,job_id):
    """
    Extrae información SIP del payload:
      - User-Agent (y parseo con DeviceDetector si está disponible)
      - From
      - To
      - Via (y extrae IP si existe)

    Añade varias filas al batch, una por cada campo importante para mantener formato simple.
    """
    try:
        if not raw or len(raw) < 20:
            return batch

        # Detectar SIP básico (INVITE/REGISTER/ACK/BYE/... o SIP/2.0)
        if not any(k in raw for k in (b"INVITE ", b"REGISTER ", b"BYE ", b"ACK ", b"OPTIONS ",
                                     b"CANCEL ", b"MESSAGE ", b"SIP/2.0")):
            return batch

        payload_str = raw.decode(errors="ignore")

        # safe src_so
        try:
            src_so = return_ttl_so_name(ttl_number)
        except Exception:
            src_so = "unknown"

        # --- User-Agent ---
        ua_match = re.search(r'(?im)^\s*User-Agent\s*:\s*(.+)$', payload_str, flags=re.MULTILINE)
        if ua_match:
            ua_str = ua_match.group(1).strip()
            # parse UA con DeviceDetector si está disponible
            try:
                dd = DeviceDetector(ua_str).parse()
                ua_parsed = parse(ua_str)
                ua_parsed_string = f"Aplicacion: {ua_parsed.browser.family} {ua_parsed.browser.version_string}, SO: {ua_parsed.os.family} {ua_parsed.os.version_string}, Dispositivo: {ua_parsed.device.family}"
                ua_parsed_inspect = parse_user_agent(ua, android_models)
            except Exception:
                logger.error(f"job:{job_id}:Error parseando user agent string {ua_str}")
                # fallback simple
                ua_parsed = ""
                ua_parsed_string=""
                ua_parsed_inspect=""
            batch.append([ts, src, dst, src_so, "SIP", "user_agent", ua_str, ua_parsed,ua_parsed_string,ua_parsed_inspect])

        # --- From ---
        from_match = re.search(r'(?im)^\s*From\s*:\s*(.+)$', payload_str, flags=re.MULTILINE)
        if from_match:
            from_str = from_match.group(1).strip()
            batch.append([ts, src, dst, src_so, "SIP", "from", from_str])

        # --- To ---
        to_match = re.search(r'(?im)^\s*To\s*:\s*(.+)$', payload_str, flags=re.MULTILINE)
        if to_match:
            to_str = to_match.group(1).strip()
            batch.append([ts, src, dst, src_so, "SIP", "to", to_str])

        # --- Via (puede haber múltiples líneas Via) ---
        via_matches = re.findall(r'(?im)^\s*Via\s*:\s*(.+)$', payload_str, flags=re.MULTILINE)
        for via_full in via_matches:
            via_full = via_full.strip()
            # intentar extraer la IP/host dentro de la cabecera Via
            # patrones típicos: "SIP/2.0/UDP 192.0.2.1:5060;branch=..." or "SIP/2.0/UDP [2001:db8::1]:5060;..."
            ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', via_full)  # IPv4 simple
            if not ip_match:
                # intentar IPv6 en corchetes
                ip_match = re.search(r'\[([0-9a-fA-F:]+)\]', via_full)
            via_ip = ip_match.group(1) if ip_match else ""
            batch.append([ts, src, dst, src_so, "SIP", "via", via_full, via_ip])

        # --- Contact (opcional; puede contener SIP URI con IP) ---
        contact_match = re.search(r'(?im)^\s*Contact\s*:\s*(.+)$', payload_str, flags=re.MULTILINE)
        if contact_match:
            contact_str = contact_match.group(1).strip()
            batch.append([ts, src, dst, src_so, "SIP", "contact", contact_str])

    except Exception as e:
        logger.debug(f"job:{job_id}:Error en search_sip_info: {e}",exc_info=True)

    return batch



def pyshark_packet_analysis(pcap_path: str, frame_number: int):
    """
    Analiza solo un paquete (por número de frame) con PyShark.
    Devuelve protocolo de aplicación o información extendida.
    """
    try:
        #logger.debug(f"Analizando frame{frame_number} con pyshark")
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
        info= None
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

def extract_sni_from_stream(packets):
    """Busca el primer ClientHello y extrae el SNI."""
    for pkt in packets:
        if hasattr(pkt, 'tls'):
            if hasattr(pkt.tls, 'handshake_type') and pkt.tls.handshake_type == '1':
                if hasattr(pkt.tls, 'handshake_extensions_server_name'):
                    return pkt.tls.handshake_extensions_server_name
    return None

def build_frame_sni_map(pcap_path: str,job_id):
    """
    Devuelve un diccionario {frame_number: SNI} para todos los ClientHello TLS del PCAP.
    Maneja tanto paquetes fragmentados como no fragmentados.
    """
    frame_sni_map = {}
    stream_sni_cache = {}  # Para no recargar el mismo stream varias veces

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

                """
                # No necesario porque con los override_prefs definidos ya se reensamblan los paquetes fragmentados
                
                # Paquete fragmentado: solo segment_data
                if not sni and "segment_data" in pkt.tls.field_names:
                    stream_id = int(pkt.tcp.stream)
                    logger.debug(f"job:{job_id}:Paquete fragmentado frame {frame_number}, stream {stream_id}")
                    if stream_id in stream_sni_cache:
                        sni = stream_sni_cache[stream_id]
                    else:
                        #Cargar el stream
                        with pyshark.FileCapture(
                            pcap_path,
                            display_filter=f"tcp.stream == {stream_id}",
                            keep_packets=True,
                            override_prefs={
                                "tcp.desegment_tcp_streams": "TRUE",
                                "tls.desegment_ssl_records": "TRUE",
                                "tls.desegment_ssl_application_data": "TRUE",
                                "tcp.analyze_sequence_numbers": "TRUE"
                            }
                        ) as stream_cap:
                            stream_cap.load_packets()
                            sni = extract_sni_from_stream(stream_cap)
                            stream_cap.close()
                """
            if sni:
                frame_sni_map[frame_number] = sni

    return frame_sni_map

def is_stun_packet(payload: bytes) -> bool:
    """
    Detecta si un payload UDP/TCP corresponde a un mensaje STUN.
    """
    if len(payload) < 20:  # mínimo tamaño header STUN
        return False
    # Magic cookie bytes 4-7 (big endian)
    magic_cookie = payload[4:8]
    if magic_cookie == b'\x21\x12\xa4\x42':
        return True
    return False

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


def search_stun_info(batch, raw, ts_packet,file_name, src,src_so, dst,dst_port):
    if is_stun_packet(raw):
        #logger.debug(f"job:{job_id}:detectado paquete stun en UDP: paquete {packet_count}")

        # Message Type (2 bytes, big endian)
        msg_type = int.from_bytes(raw[0:2], byteorder='big')

        if msg_type == 0x0001:
            #Binding Request
            if not ip_address(dst).is_private:
                ts_now = datetime.now().isoformat()
                batch.append([ts_now,file_name,ts_packet, src, src_so, dst, "STUN CALL", "to ip", dst, "to port", dst_port])

            return batch
        elif msg_type == 0x103:
            #Allocate Success Response
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
                    batch.append([ts_now,file_name,ts_packet, src,src_so, dst, "STUN CALL", "from ip", xip, "from port", xport])

                # pasar al siguiente atributo (alineado a 4 bytes)
                offset += 4 + ((attr_len + 3) // 4) * 4
            return batch
        """
        else:
            logger.debug(f"otro {msg_type}")
            return batch
        """
    return batch
