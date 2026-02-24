"""
generer_qrcode.py
Génère les QR codes TOTP pour Google Authenticator
depuis la base de données existante
"""

import sqlite3
import pyotp
import qrcode
import os

DB_PATH = "bmi_auth.db"

def recuperer_utilisateurs():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.execute(
        "SELECT username, totp_secret FROM users"
    )
    users = [(row["username"], row["totp_secret"])
             for row in cursor.fetchall()]
    conn.close()
    return users

def generer_qrcode_utilisateur(username, secret):
    """
    Génère un QR code PNG scannable par Google Authenticator
    """
    totp = pyotp.TOTP(secret)

    # URI standard otpauth://
    uri = totp.provisioning_uri(
        name=username,
        issuer_name="BMI_Usine_GDIZ"
    )

    print(f"\nUtilisateur : {username}")
    print(f"Secret      : {secret}")
    print(f"Code actuel : {totp.now()}")
    print(f"URI TOTP    : {uri}")

    # Générer image QR
    img = qrcode.make(uri)
    nom_fichier = f"qr_{username.replace('@','_').replace('.','_')}.png"
    img.save(nom_fichier)
    print(f"QR code sauvé : {nom_fichier}")

    return nom_fichier

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("ERREUR : Lancez d'abord python database.py")
        exit(1)

    utilisateurs = recuperer_utilisateurs()

    if not utilisateurs:
        print("ERREUR : Aucun utilisateur en base")
        exit(1)

    print("=" * 50)
    print("  GÉNÉRATION DES QR CODES TOTP — BMI")
    print("=" * 50)

    fichiers = []
    for username, secret in utilisateurs:
        f = generer_qrcode_utilisateur(username, secret)
        fichiers.append(f)

    print("\n" + "=" * 50)
    print("INSTRUCTIONS :")
    print("1. Ouvrez Google Authenticator sur votre téléphone")
    print("2. Appuyez sur + puis 'Scanner un QR code'")
    print("3. Scannez le fichier PNG correspondant")
    print("   (ouvrez-le en grand sur votre écran)")
    print("=" * 50)
    print("\nFichiers générés :")
    for f in fichiers:
        print(f"  {f}")
