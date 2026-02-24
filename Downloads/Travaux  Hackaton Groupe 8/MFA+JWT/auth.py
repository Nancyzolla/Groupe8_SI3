"""
auth.py — BMI Auth v2.0
MFA TOTP + JWT RS256 + Refresh rotatif + Anti brute-force
Logging via logger_bmi.py → auth_bmi.log + security.log
"""

import pyotp
import jwt
import uuid
import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Logger centralisé — doit être importé EN PREMIER
from database import get_must_change, set_must_change
from logger_bmi import (
    auth_logger,
    log_connexion,
    log_action,
    log_securite
)

import time

DB_PATH              = "bmi_auth.db"
MAX_TENTATIVES       = 5
FENETRE_TENTATIVES   = 300    # 5 min — fenêtre comptage échecs
DUREE_BLOCAGE        = 300    # 5 min — durée du blocage
SEUIL_BRUTE_FORCE    = 20     # échecs sur 10 min → blocage long
FENETRE_BRUTE_FORCE  = 600    # 10 min — fenêtre brute-force agressive
JWT_EXPIRATION       = 15     # minutes
REFRESH_EXPIRATION   = 7      # jours

# ============================================================
# CLÉS RSA
# ============================================================

auth_logger.info("Génération clés RSA 2048 bits...")

_pk = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
CLE_PRIVEE = _pk.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
CLE_PUBLIQUE = _pk.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

auth_logger.info("Clés RSA générées avec succès")

# ============================================================
# DB
# ============================================================

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ============================================================
# JOURNALISER (appelé depuis app.py)
# ============================================================

def journaliser(username, ip, action, succes, raison=""):
    """Wrapper public appelé depuis app.py."""
    if action == "LOGIN":
        log_connexion(username, ip, succes, raison)
    else:
        log_action(username, ip, action, succes, raison)

# ============================================================
# ANTI BRUTE-FORCE — timestamps entiers (time.time())
# ============================================================

def enregistrer_tentative(username, ip, succes):
    """Enregistre une tentative (succès ou échec) avec timestamp UNIX."""
    try:
        conn = get_connection()
        conn.execute("""
            INSERT INTO auth_logs (username, ip_address, action, succes, raison)
            VALUES (?, ?, 'LOGIN', ?, ?)
        """, (username, ip, int(succes),
              "OK" if succes else "Echec mot de passe"))
        conn.commit()
        conn.close()
    except Exception as e:
        auth_logger.error(f"Erreur enregistrer_tentative : {e}")


def compter_tentatives_recentes(username, ip, fenetre=None):
    """Compte les échecs de connexion dans la fenêtre glissante."""
    if fenetre is None:
        fenetre = FENETRE_TENTATIVES
    try:
        conn   = get_connection()
        limite = int(time.time()) - fenetre
        # auth_logs stocke le timestamp comme TEXT ISO
        # on compare directement avec datetime('now', '-Xs')
        cursor = conn.execute("""
            SELECT COUNT(*) FROM auth_logs
            WHERE username = ? AND ip_address = ?
              AND succes = 0
              AND timestamp > datetime('now', ? || ' seconds')
        """, (username, ip, f"-{fenetre}"))
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except Exception as e:
        auth_logger.error(f"Erreur compter_tentatives : {e}")
        return 0


def enregistrer_tentative_echouee(username, ip):
    """Enregistre un échec et loggue avec le bon compteur."""
    enregistrer_tentative(username, ip, False)
    nb = compter_tentatives_recentes(username, ip)
    auth_logger.warning(
        f"ECHEC LOGIN | user={username} | ip={ip} "
        f"| tentative {nb}/{MAX_TENTATIVES}"
    )
    if nb >= 3:
        log_securite(
            "TENTATIVES_MULTIPLES",
            f"user={username} ip={ip} nb={nb}/{MAX_TENTATIVES}",
            niveau="WARNING"
        )


def reinitialiser_tentatives(username, ip):
    """Supprime les tentatives après connexion réussie."""
    try:
        conn = get_connection()
        conn.execute("""
            DELETE FROM auth_logs
            WHERE username = ? AND ip_address = ?
              AND succes = 0
              AND action = 'LOGIN'
        """, (username, ip))
        conn.commit()
        conn.close()
        auth_logger.info(
            f"Tentatives réinitialisées | user={username} ip={ip}"
        )
    except Exception as e:
        auth_logger.error(f"Erreur reinitialiser_tentatives : {e}")


def est_bloque(username, ip):
    """
    Retourne (True, temps_restant) si bloqué, sinon (False, 0).
    Deux niveaux :
    - Normal : 5 échecs / 5 min → bloqué 5 min
    - Brute-force : 20 échecs / 10 min → bloqué 10 min
    """
    # Niveau 1 — brute-force agressive
    echecs_lourds = compter_tentatives_recentes(
        username, ip, FENETRE_BRUTE_FORCE
    )
    if echecs_lourds >= SEUIL_BRUTE_FORCE:
        log_securite(
            "BRUTE_FORCE_DETECTE",
            f"user={username} ip={ip} echecs={echecs_lourds}",
            niveau="CRITICAL"
        )
        return True, DUREE_BLOCAGE * 2  # 10 min

    # Niveau 2 — blocage normal
    echecs = compter_tentatives_recentes(username, ip, FENETRE_TENTATIVES)
    if echecs >= MAX_TENTATIVES:
        # Calculer le temps restant depuis le dernier échec
        try:
            conn   = get_connection()
            cursor = conn.execute("""
                SELECT timestamp FROM auth_logs
                WHERE username = ? AND ip_address = ?
                  AND succes = 0 AND action = 'LOGIN'
                ORDER BY timestamp DESC LIMIT 1
            """, (username, ip))
            row = cursor.fetchone()
            conn.close()

            if row:
                from datetime import datetime as dt
                derniere = dt.fromisoformat(str(row["timestamp"]))
                ecoule   = (dt.now() - derniere).total_seconds()
                restant  = int(DUREE_BLOCAGE - ecoule)
                if restant > 0:
                    auth_logger.warning(
                        f"COMPTE BLOQUE | user={username} ip={ip} "
                        f"| restant={restant}s"
                    )
                    log_securite(
                        "COMPTE_BLOQUE",
                        f"user={username} ip={ip} restant={restant}s",
                        niveau="WARNING"
                    )
                    return True, restant
        except Exception as e:
            auth_logger.error(f"Erreur calcul temps restant : {e}")
            return True, DUREE_BLOCAGE  # fallback

    return False, 0

# ============================================================
# VÉRIFICATION MOT DE PASSE
# ============================================================

def verifier_mot_de_passe(username, mot_de_passe):
    """Compatible Argon2 (nouveaux comptes) et SHA-256 (anciens)."""
    conn = get_connection()
    row  = conn.execute("""
        SELECT password_hash FROM users
        WHERE username = ? AND actif = 1
    """, (username,)).fetchone()
    conn.close()

    if not row:
        auth_logger.warning(
            f"Utilisateur inconnu ou inactif : {username}"
        )
        return False

    stored = row["password_hash"]

    if stored.startswith("$argon2"):
        try:
            from argon2 import PasswordHasher
            from argon2.exceptions import VerifyMismatchError
            PasswordHasher().verify(stored, mot_de_passe)
            return True
        except Exception:
            return False

    # SHA-256
    return hashlib.sha256(
        mot_de_passe.encode()
    ).hexdigest() == stored

# ============================================================
# TOTP
# ============================================================

def verifier_totp(username, code_totp):
    conn = get_connection()
    row  = conn.execute(
        "SELECT totp_secret FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()

    if not row:
        auth_logger.error(
            f"Secret TOTP introuvable : {username}"
        )
        return False

    valide = pyotp.TOTP(row["totp_secret"]).verify(
        code_totp, valid_window=1
    )

    if not valide:
        auth_logger.warning(
            f"TOTP invalide | user={username} "
            f"| code={code_totp}"
        )
    return valide

# ============================================================
# JWT RS256
# ============================================================

def _get_role(username):
    conn = get_connection()
    row  = conn.execute(
        "SELECT role FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()
    return row["role"] if row else "inconnu"


def creer_jwt(username):
    role         = _get_role(username)
    must_changer = get_must_change(username)
    now          = datetime.now(timezone.utc)
    jti          = str(uuid.uuid4())

    payload = {
        "sub":          username,
        "role":         role,
        "must_changer": must_changer,  # True = doit changer son mdp
        "iat":          now,
        "exp":          now + timedelta(minutes=JWT_EXPIRATION),
        "jti":          jti
    }
    token = jwt.encode(payload, CLE_PRIVEE, algorithm="RS256")
    auth_logger.info(
        f"JWT créé | user={username} role={role} "
        f"must_changer={must_changer} "
        f"jti={jti[:8]}... expire={JWT_EXPIRATION}min"
    )
    return token


def verifier_jwt(token):
    try:
        payload = jwt.decode(
            token, CLE_PUBLIQUE, algorithms=["RS256"]
        )
        return payload
    except jwt.ExpiredSignatureError:
        auth_logger.warning("JWT expiré présenté")
        return {"erreur": "Token expiré"}
    except jwt.InvalidTokenError as e:
        auth_logger.warning(f"JWT invalide : {e}")
        return {"erreur": f"Token invalide : {e}"}

# ============================================================
# REFRESH TOKENS
# ============================================================

def creer_refresh_token(username):
    token  = str(uuid.uuid4())
    expire = datetime.now() + timedelta(days=REFRESH_EXPIRATION)

    conn = get_connection()
    conn.execute("""
        INSERT INTO refresh_tokens
            (token, username, expires_at)
        VALUES (?, ?, ?)
    """, (token, username,
          expire.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

    auth_logger.info(
        f"Refresh token créé | user={username} "
        f"expire={expire.strftime('%Y-%m-%d')}"
    )
    return token


def renouveler_tokens(refresh_token):
    conn = get_connection()
    row  = conn.execute(
        "SELECT * FROM refresh_tokens WHERE token = ?",
        (refresh_token,)
    ).fetchone()

    if not row:
        conn.close()
        auth_logger.warning("Refresh token inconnu présenté")
        return None, None, "Token inconnu"

    expire = datetime.strptime(
        row["expires_at"], "%Y-%m-%d %H:%M:%S"
    )

    if datetime.now() > expire:
        conn.execute(
            "DELETE FROM refresh_tokens WHERE token = ?",
            (refresh_token,)
        )
        conn.commit()
        conn.close()
        auth_logger.warning(
            f"Refresh expiré | user={row['username']}"
        )
        return None, None, "Token expiré"

    if row["utilise"]:
        # VOL DE TOKEN
        username = row["username"]
        conn.execute(
            "DELETE FROM refresh_tokens WHERE username = ?",
            (username,)
        )
        conn.commit()
        conn.close()
        log_securite(
            "VOL_TOKEN_DETECTE",
            f"Réutilisation refresh token ! "
            f"user={username} — tous tokens révoqués",
            niveau="CRITICAL"
        )
        return None, None, "Token compromis"

    username = row["username"]
    conn.execute(
        "UPDATE refresh_tokens SET utilise=1 WHERE token=?",
        (refresh_token,)
    )
    conn.commit()
    conn.close()

    nouveau_jwt     = creer_jwt(username)
    nouveau_refresh = creer_refresh_token(username)
    auth_logger.info(
        f"Tokens renouvelés | user={username}"
    )
    return nouveau_jwt, nouveau_refresh, "OK"

# ============================================================
# CONNEXION COMPLÈTE
# ============================================================

def connexion_complete(username, mot_de_passe,
                       code_totp, ip="127.0.0.1"):
    """
    Flux MFA complet. Loggue chaque étape.
    """
    auth_logger.info(
        f"TENTATIVE | user={username} | ip={ip}"
    )

    # 1. Blocage — récupérer le temps restant réel
    bloque, temps_restant = est_bloque(username, ip)
    if bloque:
        log_connexion(username, ip, False,
                      f"Compte bloqué ({temps_restant}s restantes)")
        return {
            "succes":         False,
            "message":        "Compte bloque",
            "temps_restant":  temps_restant,
            "tentatives_restantes": 0
        }

    # 2. Mot de passe
    if not verifier_mot_de_passe(username, mot_de_passe):
        enregistrer_tentative_echouee(username, ip)
        nb = compter_tentatives_recentes(username, ip)
        log_connexion(username, ip, False,
                      f"Mauvais mot de passe ({nb}/{MAX_TENTATIVES})")
        return {
            "succes":  False,
            "message": f"Identifiants incorrects "
                       f"({nb}/{MAX_TENTATIVES})"
        }

    # 3. TOTP
    if not verifier_totp(username, code_totp):
        enregistrer_tentative_echouee(username, ip)
        nb = compter_tentatives_recentes(username, ip)
        log_connexion(username, ip, False,
                      f"TOTP invalide ({nb}/{MAX_TENTATIVES})")
        return {
            "succes":  False,
            "message": f"Code TOTP invalide "
                       f"({nb}/{MAX_TENTATIVES})"
        }

    # 4. SUCCÈS
    reinitialiser_tentatives(username, ip)
    role          = _get_role(username)
    access_token  = creer_jwt(username)
    refresh_token = creer_refresh_token(username)

    log_connexion(username, ip, True)
    log_securite(
        "CONNEXION_REUSSIE",
        f"user={username} ip={ip} role={role}",
        niveau="INFO"
    )

    must_changer = get_must_change(username)

    return {
        "succes":        True,
        "message":       "Connexion réussie",
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "expires_in":    f"{JWT_EXPIRATION} minutes",
        "role":          role,
        "must_changer":  must_changer
    }
