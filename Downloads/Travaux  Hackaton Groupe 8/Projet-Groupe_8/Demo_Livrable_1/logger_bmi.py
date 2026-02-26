"""
logger_bmi.py — Système de logging centralisé BMI
Point d'entrée unique pour tous les logs.
Importer ce fichier dans auth.py et detecteur.py.
"""

import logging
import os
import sqlite3
from datetime import datetime

DB_PATH = "bmi_auth.db"


def _preparer_fichier(chemin):
    if not os.path.exists(chemin):
        open(chemin, "w").close()
    return chemin


def _creer_logger(nom, fichier, niveau_console=logging.WARNING,
                  couleur="\033[0m"):
    """
    Crée un logger propre avec 1 handler fichier + 1 console.
    Si déjà créé, le retourne sans dupliquer les handlers.
    """
    logger = logging.getLogger(nom)

    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    # Handler fichier — écrit TOUT (DEBUG+)
    fh = logging.FileHandler(
        _preparer_fichier(fichier),
        encoding="utf-8",
        mode="a"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(fh)

    # Handler console — WARNING+ avec couleur
    ch = logging.StreamHandler()
    ch.setLevel(niveau_console)
    ch.setFormatter(logging.Formatter(
        couleur + "[%(asctime)s] %(message)s\033[0m",
        datefmt="%H:%M:%S"
    ))
    logger.addHandler(ch)

    return logger


# ============================================================
# LES 3 LOGGERS
# ============================================================

auth_logger = _creer_logger(
    "bmi.auth", "auth_bmi.log",
    niveau_console=logging.INFO,
    couleur="\033[96m"   # cyan
)

security_logger = _creer_logger(
    "bmi.security", "security.log",
    niveau_console=logging.WARNING,
    couleur="\033[93m"   # jaune
)

ids_logger = _creer_logger(
    "bmi.ids", "ids_bmi.log",
    niveau_console=logging.WARNING,
    couleur="\033[91m"   # rouge
)


# ============================================================
# FONCTIONS PUBLIQUES
# ============================================================

def log_connexion(username, ip, succes, raison=""):
    """auth_bmi.log + table auth_logs"""
    statut = "SUCCES" if succes else "ECHEC"
    msg    = f"LOGIN {statut} | user={username} | ip={ip}"
    if raison:
        msg += f" | {raison}"
    (auth_logger.info if succes else auth_logger.warning)(msg)
    _db_auth(username, ip, "LOGIN", succes, raison)


def log_action(username, ip, action, succes, raison=""):
    """auth_bmi.log + table auth_logs"""
    statut = "OK" if succes else "KO"
    msg    = f"{action} {statut} | user={username} | ip={ip}"
    if raison:
        msg += f" | {raison}"
    (auth_logger.info if succes else auth_logger.warning)(msg)
    _db_auth(username, ip, action, succes, raison)


def log_securite(evenement, detail, niveau="WARNING"):
    """security.log"""
    msg = f"{evenement} | {detail}"
    getattr(security_logger,
            niveau.lower(), security_logger.warning)(msg)


def log_ids(ip, type_attaque, severite, detail):
    """ids_bmi.log"""
    msg    = f"{type_attaque} | ip={ip} | {detail}"
    niveaux = {
        "INFO":     ids_logger.info,
        "MEDIUM":   ids_logger.warning,
        "HIGH":     ids_logger.error,
        "CRITICAL": ids_logger.critical,
    }
    niveaux.get(severite, ids_logger.warning)(msg)


def _db_auth(username, ip, action, succes, raison=""):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT INTO auth_logs
                (username, ip_address, action, succes, raison)
            VALUES (?, ?, ?, ?, ?)
        """, (username, ip, action, int(succes), raison or ""))
        conn.commit()
        conn.close()
    except Exception as e:
        auth_logger.error(f"Erreur DB auth_logs : {e}")


def tester_loggers():
    """Écrit une ligne de test dans chaque fichier au démarrage."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    auth_logger.info(
        f"=== Serveur BMI démarré {now} — auth_bmi.log OK ==="
    )
    security_logger.info(
        f"=== Serveur BMI démarré {now} — security.log OK ==="
    )
    ids_logger.info(
        f"=== Serveur BMI démarré {now} — ids_bmi.log OK ==="
    )
    print("  Logs actifs :")
    for f in ["auth_bmi.log", "security.log", "ids_bmi.log"]:
        taille = os.path.getsize(f) if os.path.exists(f) else 0
        print(f"  ✓ {f:<18} ({taille} octets) "
              f"→ {os.path.abspath(f)}")
