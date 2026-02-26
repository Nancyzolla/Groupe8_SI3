"""
serveur.py
Lance BMI Auth en mode production avec Waitress.
Supporte plusieurs connexions simultanées.
"""

import socket
from waitress import serve
from app import app
from database import initialiser_db, creer_utilisateurs_test
from app import init_table_qr_scans
from detecteur import init_tables_ids
import pyotp

def get_ip_locale():
    """Récupère l'IP locale de la machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

if __name__ == "__main__":
    print("Initialisation BMI Auth System...")
    initialiser_db()
    init_table_qr_scans()
    init_tables_ids()      # Correction : tables IDS manquantes
    secrets = creer_utilisateurs_test()

    ip = get_ip_locale()

    print("\n" + "=" * 55)
    print("  BMI AUTH — SERVEUR RÉSEAU")
    print("=" * 55)

    print("\nCOMPTES DE TEST :")
    for username, info in secrets.items():
        code = pyotp.TOTP(info["secret"]).now()
        print(f"\n  {username}")
        print(f"  Mot de passe : {info['password']}")
        print(f"  Code TOTP    : {code} (30s)")

    print("\n" + "=" * 55)
    print("ACCÈS RÉSEAU :")
    print(f"  Ce PC         : http://localhost:5000/login-page")
    print(f"  Autres PC     : http://{ip}:5000/login-page")
    print(f"  API           : http://{ip}:5000/")
    print("=" * 55)
    print("\nServeur démarré — Ctrl+C pour arrêter\n")

    # Lancer Waitress (multi-threadé, stable)
    serve(
        app,
        host="0.0.0.0",
        port=5000,
        threads=8          # 8 connexions simultanées
    )
