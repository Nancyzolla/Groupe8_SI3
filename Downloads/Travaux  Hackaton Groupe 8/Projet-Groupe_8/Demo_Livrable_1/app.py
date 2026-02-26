"""
app.py — BMI Auth v2.0 CORRIGÉ
Middleware IDS sécurisé — ne crashe plus si table absente.
"""

import io
import base64
import sqlite3
import secrets as secrets_module

import pyotp
import qrcode

from flask import (
    Flask, request, jsonify,
    make_response, render_template,
    render_template_string
)
from functools import wraps

# Import IDS — init_tables_ids() s'exécute automatiquement ici
from detecteur import (
    analyser_requete,
    init_tables_ids,
    enregistrer_alerte
)

from auth import (
    connexion_complete, verifier_jwt,
    renouveler_tokens, journaliser,
    est_bloque, verifier_mot_de_passe,
    enregistrer_tentative, enregistrer_tentative_echouee,
    reinitialiser_tentatives, compter_tentatives_recentes,
    MAX_TENTATIVES
)
from database import initialiser_db, creer_utilisateurs_test, set_must_change
from password_policy import (
    valider_mot_de_passe, sauvegarder_mot_de_passe
)

app = Flask(__name__)

# ============================================================
# HELPERS DB
# ============================================================

def db():
    conn = sqlite3.connect("bmi_auth.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_table_qr_scans():
    conn = db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS qr_scans (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL,
            token      TEXT UNIQUE NOT NULL,
            scanne     INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# ============================================================
# MIDDLEWARE IDS — INTERCEPTE TOUTES LES REQUÊTES
# ============================================================

# Routes qui ont leur propre anti-brute-force dans auth.py
# → le middleware IDS ne doit PAS les bloquer par fréquence
ROUTES_AUTH = {"/check-credentials", "/login", "/refresh",
               "/api/qr-code", "/api/qr-status", "/api/qr-confirmer"}

@app.before_request
def middleware_ids():
    """
    Analyse chaque requête avant qu'elle arrive aux routes.
    Les routes d'authentification sont exemptées du compteur
    de fréquence IDS — elles ont leur propre brute-force.
    """
    if request.path.startswith("/static"):
        return None

    try:
        ip         = request.remote_addr or "0.0.0.0"
        method     = request.method
        path       = request.path
        user_agent = request.headers.get("User-Agent", "")
        token      = None
        username   = None
        data       = None

        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth.split(" ")[1]

        if request.is_json:
            try:
                body     = request.get_json(silent=True) or {}
                username = body.get("username")
                data     = body
            except Exception:
                pass

        # Routes auth : vérifier uniquement injection + IP bannie
        # Pas de compteur de fréquence (géré par auth.py)
        if path in ROUTES_AUTH:
            bloquee, raison = analyser_requete(
                ip, method, path, user_agent,
                data=data, token=token, username=username,
                ignorer_frequence=True   # ← nouveau paramètre
            )
        else:
            bloquee, raison = analyser_requete(
                ip, method, path, user_agent,
                data=data, token=token, username=username
            )

        if bloquee:
            return jsonify({
                "erreur":  "Accès refusé",
                "raison":  raison,
                "contact": "admin@bmi.bj"
            }), 403

    except Exception as e:
        # Ne jamais crasher le serveur à cause du middleware
        app.logger.error(f"Erreur middleware IDS : {e}")

    return None

# ============================================================
# DÉCORATEUR AUTH
# ============================================================

def requiert_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"erreur": "Token manquant"}), 401
        token   = auth_header.split(" ")[1]
        payload = verifier_jwt(token)
        if "erreur" in payload:
            return jsonify(payload), 401
        request.utilisateur = payload
        return f(*args, **kwargs)
    return wrapper

# ============================================================
# DÉCORATEUR — BLOCAGE SI MOT DE PASSE TEMPORAIRE
# ============================================================

def verifie_mdp(f):
    """
    À utiliser APRÈS @requiert_auth sur les routes métier.
    Bloque l'accès si l'utilisateur doit changer son mot de passe.
    Retourne 403 avec must_changer=True pour que le front redirige.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.utilisateur.get("must_changer"):
            return jsonify({
                "erreur":        "Changement de mot de passe requis",
                "must_changer":  True,
                "redirection":   "/change-password"
            }), 403
        return f(*args, **kwargs)
    return wrapper

# ============================================================
# ROUTES PUBLIQUES
# ============================================================

@app.route("/")
def index():
    return jsonify({
        "service": "BMI Auth API",
        "version": "2.0",
        "endpoints": [
            "GET  /login-page           -> Formulaire",
            "POST /check-credentials    -> Verif mot de passe",
            "GET  /api/qr-code          -> QR code TOTP",
            "GET  /api/qr-status        -> Polling scan",
            "POST /api/qr-confirmer     -> Confirmer scan",
            "POST /login                -> Connexion MFA",
            "POST /refresh              -> Renouveler JWT",
            "POST /change-password      -> Changer mdp",
            "GET  /api/capteurs         -> Donnees (auth)",
            "GET  /api/logs             -> Logs (admin)",
            "GET  /api/status           -> Statut API",
        ]
    })

@app.route("/api/status")
def status():
    return jsonify({"statut": "BMI Auth operationnelle"})

@app.route("/login-page")
def login_page():
    return render_template("login.html")

# ============================================================
# ETAPE 1 — VERIFICATION CREDENTIALS
# ============================================================

@app.route("/check-credentials", methods=["POST"])
def check_credentials():
    data     = request.get_json()
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    ip       = request.remote_addr

    if not username or not password:
        return jsonify({"message": "Champs manquants"}), 400

    # Vérifier blocage — retourne (True, temps_restant) ou (False, 0)
    bloque, temps_restant = est_bloque(username, ip)
    if bloque:
        return jsonify({
            "message":              "Compte temporairement bloque",
            "temps_restant":        temps_restant,
            "tentatives_restantes": 0
        }), 429

    if not verifier_mot_de_passe(username, password):
        enregistrer_tentative_echouee(username, ip)

        # Compter après insertion → valeur exacte
        echecs    = compter_tentatives_recentes(username, ip)
        restantes = max(0, MAX_TENTATIVES - echecs)

        return jsonify({
            "message":              "Identifiants incorrects",
            "tentatives_restantes": restantes
        }), 401

    # Succès — enregistrer et réinitialiser les échecs
    enregistrer_tentative(username, ip, True)
    reinitialiser_tentatives(username, ip)

    return jsonify({"message": "OK"}), 200

# ============================================================
# QR CODE — GENERATION
# ============================================================

@app.route("/api/qr-code")
def get_qr_code():
    username = request.args.get("username", "").strip().lower()

    if not username:
        return jsonify({"erreur": "Username manquant"}), 400

    conn   = db()
    cursor = conn.execute(
        "SELECT totp_secret FROM users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({"erreur": "Utilisateur inconnu"}), 404

    secret = row["totp_secret"]

    conn.execute(
        "DELETE FROM qr_scans WHERE username = ?",
        (username,)
    )
    ticket = secrets_module.token_hex(32)
    conn.execute("""
        INSERT INTO qr_scans (username, token, scanne)
        VALUES (?, ?, 0)
    """, (username, ticket))
    conn.commit()
    conn.close()

    totp = pyotp.TOTP(secret)
    uri  = totp.provisioning_uri(
        name=username,
        issuer_name="BMI_Usine_GDIZ"
    )

    img    = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    qr_b64 = base64.b64encode(buffer.read()).decode()

    return jsonify({
        "qr_b64":   qr_b64,
        "ticket":   ticket,
        "username": username
    })

# ============================================================
# QR CODE — POLLING
# ============================================================

@app.route("/api/qr-status")
def qr_status():
    ticket   = request.args.get("ticket",   "")
    username = request.args.get("username", "").strip().lower()

    if not ticket or not username:
        return jsonify({"erreur": "Parametres manquants"}), 400

    conn   = db()
    cursor = conn.execute("""
        SELECT scanne FROM qr_scans
        WHERE token = ? AND username = ?
    """, (ticket, username))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"scanne": False, "expire": True})

    return jsonify({"scanne": bool(row["scanne"]), "expire": False})

# ============================================================
# QR CODE — CONFIRMER LE SCAN
# ============================================================

@app.route("/api/qr-confirmer", methods=["POST"])
def qr_confirmer():
    data     = request.get_json()
    ticket   = data.get("ticket",    "")
    username = data.get("username",  "").strip().lower()
    code     = data.get("totp_code", "")

    if not all([ticket, username, code]):
        return jsonify({"erreur": "Parametres manquants"}), 400

    conn   = db()
    cursor = conn.execute(
        "SELECT totp_secret FROM users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({"erreur": "Utilisateur inconnu"}), 404

    totp = pyotp.TOTP(row["totp_secret"])

    if not totp.verify(code, valid_window=1):
        conn.close()
        return jsonify({"valide": False,
                        "message": "Code TOTP incorrect"}), 400

    conn.execute("""
        UPDATE qr_scans SET scanne = 1
        WHERE token = ? AND username = ?
    """, (ticket, username))
    conn.commit()
    conn.close()

    return jsonify({"valide": True,
                    "message": "TOTP configure avec succes"})

# ============================================================
# CONNEXION MFA
# ============================================================

@app.route("/login", methods=["POST"])
def login():
    data      = request.get_json()
    username  = data.get("username",  "").strip().lower()
    password  = data.get("password",  "")
    totp_code = data.get("totp_code", "")
    ip        = request.remote_addr

    if not all([username, password, totp_code]):
        return jsonify({
            "erreur": "username, password, totp_code requis"
        }), 400

    resultat = connexion_complete(
        username, password, totp_code, ip
    )

    if not resultat["succes"]:
        # Compte bloqué → 429 avec temps_restant réel
        if resultat.get("tentatives_restantes") == 0            or "bloque" in resultat.get("message", "").lower():
            return jsonify(resultat), 429
        # Échec normal → 401 avec tentatives restantes
        echecs    = compter_tentatives_recentes(username, ip)
        resultat["tentatives_restantes"] = max(
            0, MAX_TENTATIVES - echecs
        )
        return jsonify(resultat), 401

    resp = make_response(jsonify({
        "succes":        True,
        "access_token":  resultat["access_token"],
        "expires_in":    resultat["expires_in"],
        "role":          resultat["role"],
        "message":       resultat["message"],
        "must_changer":  resultat.get("must_changer", False)
    }))
    resp.set_cookie(
        "refresh_token", resultat["refresh_token"],
        httponly=True, secure=False,
        samesite="Strict", max_age=7 * 24 * 3600
    )
    return resp, 200

# ============================================================
# REFRESH TOKEN
# ============================================================

@app.route("/refresh", methods=["POST"])
def refresh():
    old_refresh = request.cookies.get("refresh_token")
    if not old_refresh:
        return jsonify({"erreur": "Refresh token manquant"}), 401

    nv_jwt, nv_refresh, msg = renouveler_tokens(old_refresh)

    if not nv_jwt:
        return jsonify({"erreur": msg}), 401

    resp = make_response(jsonify({
        "access_token": nv_jwt,
        "message":      "Token renouvele"
    }))
    resp.set_cookie(
        "refresh_token", nv_refresh,
        httponly=True, secure=False,
        samesite="Strict", max_age=7 * 24 * 3600
    )
    return resp, 200

# ============================================================
# CHANGEMENT MOT DE PASSE
# ============================================================

@app.route("/change-password", methods=["POST"])
@requiert_auth
def change_password():
    import hashlib
    from database import get_connection

    data        = request.get_json()
    nouveau_mdp = data.get("nouveau_mot_de_passe", "")
    username    = request.utilisateur["sub"]

    valide, erreurs, score, niveau = valider_mot_de_passe(
        nouveau_mdp, username
    )
    if not valide:
        return jsonify({
            "erreur": "Mot de passe invalide",
            "details": erreurs
        }), 400

    nouveau_hash = hashlib.sha256(
        nouveau_mdp.encode()
    ).hexdigest()

    conn = get_connection()
    conn.execute("""
        UPDATE users SET password_hash = ?
        WHERE username = ?
    """, (nouveau_hash, username))
    conn.commit()
    conn.close()

    sauvegarder_mot_de_passe(username, nouveau_mdp)

    # Désactiver le flag "mot de passe temporaire"
    set_must_change(username, valeur=0)

    return jsonify({
        "message":      "Mot de passe modifie",
        "force":        f"{score}/100 ({niveau})",
        "must_changer": False   # Le front peut débloquer la navigation
    }), 200

# ============================================================
# ROUTES PROTEGEES
# ============================================================

@app.route("/api/capteurs", methods=["GET"])
@requiert_auth
@verifie_mdp
def get_capteurs():
    role = request.utilisateur.get("role")

    donnees = {
        "administrateur": {
            "capteurs": [
                "KUKA_1 a KUKA_5",
                "FANUC_1 a FANUC_12",
                "SCHULER_1 a SCHULER_8",
                "SIMOTICS_1 a SIMOTICS_3",
                "150+ capteurs IFM/OMEGA/Siemens"
            ],
            "acces": "complet"
        },
        "operateur_fanuc": {
            "capteurs": ["FANUC_1", "FANUC_2", "FANUC_3"],
            "acces": "limite CNC"
        },
        "ingenieur_maintenance": {
            "capteurs": [
                "FANUC_1 a FANUC_12",
                "KUKA_1 a KUKA_5",
                "Capteurs IFM VTV122",
                "Capteurs OMEGA OS-MINI"
            ],
            "acces": "historiques inclus"
        },
        "auditeur": {
            "capteurs": [],
            "acces": "logs uniquement"
        }
    }

    acces = donnees.get(role, {"capteurs": [], "acces": "aucun"})
    return jsonify({
        "utilisateur": request.utilisateur["sub"],
        "role":        role,
        "donnees":     acces
    }), 200

@app.route("/api/logs", methods=["GET"])
@requiert_auth
@verifie_mdp
def get_logs():
    role = request.utilisateur.get("role")

    if role not in ["administrateur", "auditeur"]:
        journaliser(
            request.utilisateur["sub"],
            request.remote_addr,
            "ACCESS_LOGS", False, "Role insuffisant"
        )
        return jsonify({"erreur": "Acces refuse"}), 403

    from database import get_connection
    conn   = get_connection()
    cursor = conn.execute("""
        SELECT username, ip_address, action,
               succes, raison, timestamp
        FROM auth_logs
        ORDER BY timestamp DESC
        LIMIT 50
    """)
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify({"logs": logs, "total": len(logs)}), 200

# ============================================================
# DEMARRAGE
# ============================================================

if __name__ == "__main__":
    print("Initialisation BMI Auth System v2.0...")

    initialiser_db()        # 1. Tables de base
    init_table_qr_scans()   # 2. Table QR scans
    init_tables_ids()       # 3. Tables IDS

    secrets = creer_utilisateurs_test()

    print("\n" + "=" * 55)
    print("COMPTES DE TEST")
    print("=" * 55)
    for username, info in secrets.items():
        code = pyotp.TOTP(info["secret"]).now()
        print(f"\n  {username}")
        print(f"  Mot de passe : {info['password']}")
        print(f"  Code TOTP    : {code} (30s)")

    print("\n" + "=" * 55)
    print("URLS")
    print("  Connexion : http://localhost:5000/login-page")
    print("  API       : http://localhost:5000/")
    print("=" * 55 + "\n")

    app.run(debug=True, host="0.0.0.0", port=5000)
