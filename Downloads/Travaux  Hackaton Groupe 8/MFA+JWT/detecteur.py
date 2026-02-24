"""
detecteur.py — BMI Auth v2.0
IDS — Détection d'intrusion.
Logging via logger_bmi.py → ids_bmi.log + security.log
Auto-initialisation à l'import.
"""

import re
import time
import sqlite3
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
from threading import Lock

from logger_bmi import log_ids, ids_logger, log_securite

DB_PATH = "bmi_auth.db"

SEUILS = {
    "bf_requetes_par_minute":    20,
    "bf_fenetre_secondes":       60,
    "scan_endpoints_differents": 15,
    "scan_fenetre_secondes":     60,
    "ddos_requetes_par_seconde": 50,
    "ddos_fenetre_secondes":      5,
    "stuffing_users_differents": 10,
    "ban_duree_minutes":         30,
    "ban_duree_severe_minutes": 1440,
}

PATTERNS_SQL = [
    r"(\bOR\b|\bAND\b)\s+[\w'\"]+\s*=\s*[\w'\"]+",
    r"(UNION\s+SELECT|INSERT\s+INTO|DROP\s+TABLE|DELETE\s+FROM)",
    r"(--|;--|/\*|\*/|xp_|exec\s*\()",
    r"('\s*OR\s*'1'\s*=\s*'1|1=1|admin'--)",
    r"(SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY)",
]
PATTERNS_XSS = [
    r"<script[\s>]", r"javascript\s*:",
    r"on(load|click|error|mouseover)\s*=",
    r"<iframe|<embed|<object", r"eval\s*\(|alert\s*\(",
]
PATTERNS_SCANNERS = [
    "sqlmap","nikto","nmap","masscan","nessus",
    "metasploit","burpsuite","dirbuster","hydra",
    "medusa","go-http-client","zgrab","nuclei","acunetix",
]

_lock             = Lock()
_requetes_par_ip  = defaultdict(list)
_endpoints_par_ip = defaultdict(lambda: defaultdict(list))
_users_par_ip     = defaultdict(set)
_tokens_vus       = defaultdict(set)
_ips_bannies      = {}


def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_tables_ids():
    try:
        conn = _conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS alertes_ids (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                type_attaque TEXT NOT NULL,
                severite TEXT NOT NULL,
                detail TEXT,
                bloque INTEGER DEFAULT 0,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS ip_bannies (
                ip TEXT PRIMARY KEY,
                raison TEXT,
                debut_ban TEXT,
                fin_ban TEXT,
                nb_bans INTEGER DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_alertes_ip ON alertes_ids(ip);
            CREATE INDEX IF NOT EXISTS idx_alertes_ts ON alertes_ids(timestamp);
        """)
        conn.commit()
        conn.close()
        ids_logger.info("Tables IDS initialisees : OK")
    except Exception as e:
        ids_logger.error(f"Erreur init_tables_ids : {e}")


def est_banni(ip):
    with _lock:
        if ip in _ips_bannies:
            fin = _ips_bannies[ip]
            if time.time() < fin:
                return True, int(fin - time.time())
            del _ips_bannies[ip]
    try:
        conn = _conn()
        row  = conn.execute(
            "SELECT fin_ban FROM ip_bannies WHERE ip=? AND fin_ban>datetime('now')",
            (ip,)
        ).fetchone()
        conn.close()
        if row:
            fin_dt = datetime.strptime(row["fin_ban"], "%Y-%m-%d %H:%M:%S")
            reste  = int((fin_dt - datetime.now()).total_seconds())
            with _lock:
                _ips_bannies[ip] = time.time() + reste
            return True, max(0, reste)
    except Exception:
        pass
    return False, 0


def bannir_ip(ip, raison, severe=False):
    duree  = SEUILS["ban_duree_severe_minutes" if severe else "ban_duree_minutes"] * 60
    fin_ts = time.time() + duree
    fin_s  = (datetime.now() + timedelta(seconds=duree)).strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        _ips_bannies[ip] = fin_ts
    try:
        conn = _conn()
        conn.execute("""
            INSERT INTO ip_bannies (ip,raison,debut_ban,fin_ban,nb_bans)
            VALUES (?,?,CURRENT_TIMESTAMP,?,1)
            ON CONFLICT(ip) DO UPDATE SET
                raison=excluded.raison,
                debut_ban=CURRENT_TIMESTAMP,
                fin_ban=excluded.fin_ban,
                nb_bans=nb_bans+1
        """, (ip, raison, fin_s))
        conn.commit()
        conn.close()
    except Exception as e:
        ids_logger.error(f"Erreur DB bannir_ip : {e}")
    log_ids(ip, "BAN_IP",
            "CRITICAL" if severe else "HIGH",
            f"duree={duree//60}min raison={raison}")
    log_securite("IP_BANNIE",
                 f"ip={ip} duree={duree//60}min raison={raison}",
                 niveau="CRITICAL" if severe else "WARNING")


def debannir_ip(ip):
    with _lock:
        _ips_bannies.pop(ip, None)
    try:
        conn = _conn()
        conn.execute("DELETE FROM ip_bannies WHERE ip=?", (ip,))
        conn.commit()
        conn.close()
    except Exception as e:
        ids_logger.error(f"Erreur DB debannir_ip : {e}")
    ids_logger.info(f"DEBAN MANUEL | ip={ip}")
    print(f"  IP {ip} debannie.")


def enregistrer_alerte(ip, type_attaque, severite, detail, bloquer=True):
    log_ids(ip, type_attaque, severite, detail)
    try:
        conn = _conn()
        conn.execute("""
            INSERT INTO alertes_ids (ip,type_attaque,severite,detail,bloque)
            VALUES (?,?,?,?,?)
        """, (ip, type_attaque, severite, detail, int(bloquer)))
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        if "no such table" in str(e):
            init_tables_ids()
        ids_logger.error(f"Erreur DB alerte : {e}")
    except Exception as e:
        ids_logger.error(f"Erreur enregistrer_alerte : {e}")
    if bloquer:
        if severite == "CRITICAL":
            bannir_ip(ip, type_attaque, severe=True)
        elif severite == "HIGH":
            bannir_ip(ip, type_attaque, severe=False)


def detecter_brute_force_ip(ip, endpoint):
    now = time.time()
    fen = SEUILS["bf_fenetre_secondes"]
    with _lock:
        h = _requetes_par_ip[ip]
        h[:] = [t for t in h if now-t < fen]
        h.append(now)
        nb = len(h)
    seuil = SEUILS["bf_requetes_par_minute"]
    if nb >= seuil*3:
        enregistrer_alerte(ip,"BRUTE_FORCE_IP","CRITICAL",f"{nb} req/{fen}s sur {endpoint}")
        return True
    if nb >= seuil*2:
        enregistrer_alerte(ip,"BRUTE_FORCE_IP","HIGH",f"{nb} req/{fen}s",bloquer=False)
    elif nb >= seuil:
        enregistrer_alerte(ip,"RATE_LIMIT","MEDIUM",f"{nb} req/{fen}s",bloquer=False)
    return False


def detecter_scan_endpoints(ip, endpoint):
    now = time.time()
    fen = SEUILS["scan_fenetre_secondes"]
    with _lock:
        h = _endpoints_par_ip[ip]
        for ep in list(h.keys()):
            h[ep] = [t for t in h[ep] if now-t < fen]
            if not h[ep]: del h[ep]
        if endpoint not in h: h[endpoint] = []
        h[endpoint].append(now)
        nb_ep = len(h)
    if nb_ep >= SEUILS["scan_endpoints_differents"]:
        enregistrer_alerte(ip,"SCAN_ENDPOINTS","HIGH",f"{nb_ep} endpoints en {fen}s")
        return True
    return False


def detecter_injection(ip, donnees):
    if not donnees: return False
    texte = str(donnees).upper()
    for p in PATTERNS_SQL:
        if re.search(p, texte, re.IGNORECASE):
            enregistrer_alerte(ip,"SQL_INJECTION","CRITICAL",f"Pattern: {p[:40]}")
            return True
    for p in PATTERNS_XSS:
        if re.search(p, str(donnees), re.IGNORECASE):
            enregistrer_alerte(ip,"XSS_ATTEMPT","HIGH",f"Pattern: {p[:40]}")
            return True
    return False


def detecter_credential_stuffing(ip, username):
    with _lock:
        _users_par_ip[ip].add(username)
        nb = len(_users_par_ip[ip])
    seuil = SEUILS["stuffing_users_differents"]
    if nb >= seuil:
        enregistrer_alerte(ip,"CREDENTIAL_STUFFING","CRITICAL",f"{nb} usernames depuis {ip}")
        return True
    if nb >= seuil//2:
        enregistrer_alerte(ip,"CREDENTIAL_STUFFING","HIGH",f"{nb} usernames",bloquer=False)
    return False


def detecter_ddos(ip):
    now = time.time()
    fen = SEUILS["ddos_fenetre_secondes"]
    with _lock:
        nb = len([t for t in _requetes_par_ip[ip] if now-t < fen])
    if nb >= SEUILS["ddos_requetes_par_seconde"]*fen:
        enregistrer_alerte(ip,"DDOS_FLOOD","CRITICAL",f"{nb} req en {fen}s")
        return True
    return False


def detecter_scanner_connu(ip, user_agent):
    if not user_agent:
        ids_logger.info(f"Req sans User-Agent | ip={ip}")
        return False
    ua = user_agent.lower()
    for s in PATTERNS_SCANNERS:
        if s in ua:
            enregistrer_alerte(ip,"OUTIL_ATTAQUE","HIGH",f"UA suspect: {user_agent[:80]}")
            return True
    return False


def detecter_replay_token(ip, token):
    if not token: return False
    h = hashlib.sha256(token.encode()).hexdigest()[:16]
    with _lock:
        if h in _tokens_vus:
            ips = _tokens_vus[h]
            if ip not in ips and len(ips) > 0:
                enregistrer_alerte(ip,"TOKEN_REPLAY","HIGH",
                    f"JWT depuis IP inconnue (connues: {list(ips)[:3]})",bloquer=False)
        else:
            _tokens_vus[h] = set()
        _tokens_vus[h].add(ip)
    return False


def detecter_path_traversal(ip, path):
    for p in [r"\.\./", r"\.\.\\", r"%2e%2e", r"/etc/passwd", r"/windows/system32"]:
        if re.search(p, path, re.IGNORECASE):
            enregistrer_alerte(ip,"PATH_TRAVERSAL","HIGH",f"Traversal: {path[:80]}")
            return True
    return False


def analyser_requete(ip, method, path, user_agent,
                     data=None, token=None, username=None,
                     ignorer_frequence=False):
    """
    Analyse une requete. Retourne (bloquee, raison).
    ignorer_frequence=True : routes auth exemptees du compteur
    de frequence (elles ont leur propre brute-force dans auth.py).
    """
    ids_logger.debug(
        f"REQ {method} {path} | ip={ip} | "
        f"ua={str(user_agent or '')[:40]}"
    )

    # Toujours verifier si IP bannie
    banni, reste = est_banni(ip)
    if banni:
        ids_logger.warning(
            f"IP BANNIE | ip={ip} | {reste}s restantes"
        )
        return True, f"IP bannie — {reste}s restantes"

    # Compteurs de frequence — ignores pour routes auth
    if not ignorer_frequence:
        if detecter_ddos(ip):
            return True, "DDoS detecte"
        if detecter_brute_force_ip(ip, path):
            return True, "Brute-force detecte"
        if detecter_scan_endpoints(ip, path):
            return True, "Scan endpoints detecte"

    # Toujours verifier : injections, scanners, traversal
    if detecter_path_traversal(ip, path):
        return True, "Path traversal detecte"
    if detecter_scanner_connu(ip, user_agent):
        return True, "Outil attaque detecte"
    if data and detecter_injection(ip, data):
        return True, "Injection detectee"
    if username and detecter_credential_stuffing(ip, username):
        return True, "Credential stuffing detecte"
    if token:
        detecter_replay_token(ip, token)

    return False, ""



# AUTO-INIT
init_tables_ids()
