"""
database.py — BMI Auth
Initialise SQLite avec toutes les tables nécessaires
"""

import sqlite3
import os

DB_PATH = "bmi_auth.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def initialiser_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'operateur',
            actif INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            utilise INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip_address TEXT,
            action TEXT,
            succes INTEGER,
            raison TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tentatives (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_metadata (
            username TEXT PRIMARY KEY,
            last_changed TEXT DEFAULT CURRENT_TIMESTAMP,
            must_change INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()
    print("Base de données initialisée : bmi_auth.db")

def creer_utilisateurs_test():
    import hashlib
    import pyotp

    conn = get_connection()
    cursor = conn.cursor()

    utilisateurs = [
        {
            "username": "kofi@bmi.bj",
            "password": "MotDePasse123!",
            "role": "operateur_fanuc"
        },
        {
            "username": "admin@bmi.bj",
            "password": "AdminBMI2026!",
            "role": "administrateur"
        },
        {
            "username": "ingenieur@bmi.bj",
            "password": "Maintenance456!",
            "role": "ingenieur_maintenance"
        },
        {
            "username": "auditeur@bmi.bj",
            "password": "Audit789!",
            "role": "auditeur"
        }
    ]

    secrets_generes = {}

    for user in utilisateurs:
        password_hash = hashlib.sha256(
            user["password"].encode()
        ).hexdigest()
        totp_secret = pyotp.random_base32()
        secrets_generes[user["username"]] = {
            "secret": totp_secret,
            "password": user["password"],
            "role": user["role"]
        }

        try:
            cursor.execute("""
                INSERT INTO users
                (username, password_hash, totp_secret, role)
                VALUES (?, ?, ?, ?)
            """, (
                user["username"],
                password_hash,
                totp_secret,
                user["role"]
            ))
            print(f"Utilisateur créé : {user['username']}")
        except sqlite3.IntegrityError:
            print(f"Existe déjà : {user['username']}")

    conn.commit()
    conn.close()
    return secrets_generes

if __name__ == "__main__":
    # Supprimer ancienne DB si elle existe
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print("Ancienne base supprimée")

    initialiser_db()
    secrets = creer_utilisateurs_test()

    print("\n=== SECRETS TOTP ===")
    for username, info in secrets.items():
        import pyotp
        code = pyotp.TOTP(info["secret"]).now()
        print(f"\n  {username}")
        print(f"  Mot de passe : {info['password']}")
        print(f"  Secret TOTP  : {info['secret']}")
        print(f"  Code actuel  : {code}")
        print(f"  Rôle         : {info['role']}")


def get_must_change(username):
    """Retourne True si l'utilisateur doit changer son mot de passe."""
    conn = get_connection()
    row = conn.execute("""
        SELECT must_change FROM password_metadata
        WHERE username = ?
    """, (username,)).fetchone()
    conn.close()
    return bool(row["must_change"]) if row else False


def set_must_change(username, valeur=1):
    """Positionne le flag must_change pour un utilisateur."""
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO password_metadata
            (username, last_changed, must_change)
        VALUES (?, CURRENT_TIMESTAMP, ?)
    """, (username, int(valeur)))
    conn.commit()
    conn.close()
