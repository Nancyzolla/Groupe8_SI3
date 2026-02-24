"""
ajouter_utilisateur.py
Gestion des utilisateurs BMI — compatible avec app.py et auth.py
Utilise Argon2 pour le hashage des mots de passe.
"""

import sqlite3
import pyotp
import getpass
import re
import secrets
import string
import sys
import logging
from datetime import datetime
from argon2 import PasswordHasher
# VerifyMismatchError non utilisé — supprimé

try:
    from mailer import envoyer_credentials
    MAIL_DISPONIBLE = True
except ImportError:
    MAIL_DISPONIBLE = False

DB_PATH = "bmi_auth.db"

# Argon2 — plus sécurisé que SHA-256
ph = PasswordHasher(
    time_cost=2,        # Nombre d'itérations
    memory_cost=65536,  # 64 MB de RAM utilisés
    parallelism=2       # Threads parallèles
)

ROLES_DISPONIBLES = [
    "operateur_fanuc",
    "ingenieur_maintenance",
    "administrateur",
    "auditeur"
]

DESCRIPTIONS_ROLES = {
    "operateur_fanuc":
        "Accès CNC FANUC 1-3 uniquement",
    "ingenieur_maintenance":
        "Accès FANUC + KUKA + historiques",
    "administrateur":
        "Accès complet à tous les équipements",
    "auditeur":
        "Accès aux logs uniquement"
}

# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

def log_event(message):
    logging.info(message)
    print(f"  [LOG] {message}")

# ============================================================
# CONNEXION DB
# ============================================================

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

# ============================================================
# VALIDATIONS
# ============================================================

def verifier_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))

def verifier_mot_de_passe(mdp):
    """
    Vérifie les règles de complexité.
    Retourne (valide, message)
    """
    erreurs = []
    if len(mdp) < 8:
        erreurs.append("Minimum 8 caractères")
    if not re.search(r'[A-Z]', mdp):
        erreurs.append("Au moins une majuscule")
    if not re.search(r'[a-z]', mdp):
        erreurs.append("Au moins une minuscule")
    if not re.search(r'\d', mdp):
        erreurs.append("Au moins un chiffre")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', mdp):
        erreurs.append("Au moins un caractère spécial")

    if erreurs:
        return False, " | ".join(erreurs)
    return True, "OK"

def utilisateur_existe(username):
    conn   = get_connection()
    cursor = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,)
    )
    existe = cursor.fetchone() is not None
    conn.close()
    return existe


# ============================================================
# GÉNÉRATEUR MOT DE PASSE TEMPORAIRE
# ============================================================

def gen_mdp_temporaire():
    """
    Génère un mot de passe temporaire fort de 12 caractères.
    Conforme à la politique : maj + min + chiffre + spécial.
    """
    alpha_maj = string.ascii_uppercase
    alpha_min = string.ascii_lowercase
    chiffres  = string.digits
    speciaux  = "!@#$%&*+-"   # sous-ensemble sans quotes ni backslash

    mdp = [
        secrets.choice(alpha_maj),
        secrets.choice(alpha_maj),
        secrets.choice(alpha_min),
        secrets.choice(alpha_min),
        secrets.choice(chiffres),
        secrets.choice(chiffres),
        secrets.choice(speciaux),
        secrets.choice(speciaux),
    ]
    pool = alpha_maj + alpha_min + chiffres + speciaux
    mdp += [secrets.choice(pool) for _ in range(4)]
    secrets.SystemRandom().shuffle(mdp)
    return "".join(mdp)

# ============================================================
# CRUD UTILISATEURS
# ============================================================

def ajouter_utilisateur(username, mot_de_passe=None, role="operateur_fanuc", email_employe=None, nom_affiche=""):
    """
    Crée un nouvel utilisateur.
    - Si mot_de_passe est None → génère automatiquement un mot de passe
      temporaire fort et le marque must_change=1.
    - Sinon → utilise le mot de passe fourni sans must_change.
    Affiche toujours le mot de passe en clair dans le terminal admin.
    Retourne (totp_secret, mdp_temporaire) ou (None, None) si erreur.
    """
    mdp_temporaire = mot_de_passe is None

    if mdp_temporaire:
        mot_de_passe = gen_mdp_temporaire()

    password_hash = ph.hash(mot_de_passe)
    totp_secret   = pyotp.random_base32()

    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO users
            (username, password_hash, totp_secret, role, actif, created_at)
            VALUES (?, ?, ?, ?, 1, ?)
        """, (
            username,
            password_hash,
            totp_secret,
            role,
            datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()

        # Si mot de passe temporaire → forcer le changement à la première connexion
        if mdp_temporaire:
            conn2 = get_connection()
            conn2.execute("""
                INSERT OR REPLACE INTO password_metadata
                    (username, last_changed, must_change)
                VALUES (?, CURRENT_TIMESTAMP, 1)
            """, (username,))
            conn2.commit()
            conn2.close()

        log_event(
            f"Création utilisateur : {username} | rôle={role} "
            f"| mdp_temp={mdp_temporaire}"
        )

        # ── AFFICHAGE ADMIN ──────────────────────────────────
        print()
        print("  " + "═" * 44)
        print(f"  ✅  UTILISATEUR CRÉÉ")
        print("  " + "═" * 44)
        print(f"  Compte       : {username}")
        print(f"  Rôle         : {role}")
        print(f"  Mot de passe : {mot_de_passe}")
        if mdp_temporaire:
            print(f"  ⚠  TEMPORAIRE — l'utilisateur devra le changer")
            print(f"     à sa première connexion.")
        print("  " + "─" * 44)
        print(f"  Secret TOTP  : {totp_secret}")
        code_now = pyotp.TOTP(totp_secret).now()
        print(f"  Code actuel  : {code_now} (valable 30s)")
        print("  " + "═" * 44)
        print()

        # ── ENVOI MAIL ──────────────────────────────────────
        destinataire_mail = email_employe or username
        if mdp_temporaire and MAIL_DISPONIBLE:
            print(f"  Envoi du mail de bienvenue à {destinataire_mail}...")
            ok, err = envoyer_credentials(
                destinataire = destinataire_mail,
                username     = username,
                mdp_temp     = mot_de_passe,
                role         = role,
                nom_affiche  = nom_affiche,
            )
            if ok:
                print(f"  ✉  Mail envoyé avec succès à {destinataire_mail}")
            else:
                print(f"  ⚠  Mail non envoyé : {err}")
                print(f"     Communiquez le mot de passe ci-dessus manuellement.")
        elif mdp_temporaire and not MAIL_DISPONIBLE:
            print(f"  ⚠  Module mailer non disponible — mail non envoyé.")
            print(f"     Communiquez le mot de passe ci-dessus manuellement.")

        return totp_secret, mot_de_passe

    except sqlite3.IntegrityError:
        print(f"  ERREUR : '{username}' existe déjà en base.")
        return None, None
    finally:
        conn.close()

def lister_utilisateurs():
    """Affiche tous les utilisateurs avec leur statut."""
    conn   = get_connection()
    cursor = conn.execute("""
        SELECT id, username, role, actif,
               created_at
        FROM users
        ORDER BY id
    """)
    users = cursor.fetchall()
    conn.close()

    print("\n" + "=" * 75)
    print("  UTILISATEURS BMI")
    print("=" * 75)
    print(
        f"  {'ID':<4} {'EMAIL':<25} {'RÔLE':<25} "
        f"{'ACTIF':<6} {'ÉCHECS'}"
    )
    print("-" * 75)
    for u in users:
        statut = "Oui" if u["actif"] else "NON"
        print(
            f"  {u['id']:<4} "
            f"{u['username']:<25} "
            f"{u['role']:<25} "
            f"{statut:<6} "
            "0"  # colonne supprimée, auth_logs gère les tentatives
        )
    print("=" * 75)
    print(f"  Total : {len(users)} utilisateur(s)")

def desactiver_utilisateur(username):
    """
    Désactive un compte sans le supprimer.
    L'utilisateur ne pourra plus se connecter.
    """
    conn = get_connection()
    conn.execute("""
        UPDATE users SET actif = 0 WHERE username = ?
    """, (username,))
    conn.commit()
    modifie = conn.execute(
        "SELECT changes()"
    ).fetchone()[0]
    conn.close()

    if modifie:
        log_event(f"Désactivation : {username}")
    return modifie > 0

def reactiver_utilisateur(username):
    """Réactive un compte désactivé."""
    conn = get_connection()
    conn.execute("""
        UPDATE users
        SET actif = 1
        WHERE username = ?
    """, (username,))
    conn.commit()
    modifie = conn.execute(
        "SELECT changes()"
    ).fetchone()[0]
    conn.close()

    if modifie:
        log_event(f"Réactivation : {username}")
    return modifie > 0

def reinitialiser_totp(username):
    """
    Génère un nouveau secret TOTP.
    L'utilisateur devra rescanner le QR code
    sur /login-test.
    """
    nouveau_secret = pyotp.random_base32()
    conn = get_connection()
    conn.execute("""
        UPDATE users SET totp_secret = ? WHERE username = ?
    """, (nouveau_secret, username))
    conn.commit()
    modifie = conn.execute(
        "SELECT changes()"
    ).fetchone()[0]
    conn.close()

    if modifie:
        log_event(f"Reset TOTP : {username}")
        return nouveau_secret
    return None

def reinitialiser_echecs(username):
    """
    Remet à zéro le compteur de tentatives échouées.
    Utile si un utilisateur est bloqué injustement.
    """
    conn = get_connection()
    conn.execute("""
        UPDATE users
        SET actif = actif  -- réinitialisation via auth_logs, pas de colonne dédiée
        WHERE username = ?
    """, (username,))

    # Supprimer aussi de la table tentatives
    conn.execute("""
        DELETE FROM tentatives WHERE username = ?
    """, (username,))

    conn.commit()
    conn.close()
    log_event(f"Reset tentatives : {username}")
    print(f"  Compteur remis à zéro pour {username}")

def changer_mot_de_passe(username, nouveau_mdp):
    """
    Change le mot de passe avec validation complète
    et hash Argon2.
    """
    valide, msg = verifier_mot_de_passe(nouveau_mdp)
    if not valide:
        return False, msg

    # Vérifier que l'utilisateur existe
    if not utilisateur_existe(username):
        return False, "Utilisateur non trouvé"

    nouveau_hash = ph.hash(nouveau_mdp)

    conn = get_connection()
    conn.execute("""
        UPDATE users
        SET password_hash = ?
        WHERE username = ?
    """, (nouveau_hash, username))
    conn.commit()
    conn.close()

    log_event(f"Changement mot de passe : {username}")
    return True, "Mot de passe mis à jour avec succès"

def afficher_info_utilisateur(username):
    """Affiche les détails d'un utilisateur."""
    conn   = get_connection()
    cursor = conn.execute("""
        SELECT username, role, actif,
               created_at, totp_secret
        FROM users WHERE username = ?
    """, (username,))
    u = cursor.fetchone()
    conn.close()

    if not u:
        print(f"  Utilisateur '{username}' non trouvé.")
        return

    totp     = pyotp.TOTP(u["totp_secret"])
    code_now = totp.now()

    print("\n" + "=" * 50)
    print(f"  DÉTAILS : {username}")
    print("=" * 50)
    print(f"  Rôle          : {u['role']}")
    print(f"  Actif         : {'Oui' if u['actif'] else 'NON'}")
    # failed_attempts géré par auth_logs, non affiché ici
    print(f"  Créé le       : {u['created_at']}")
    print(f"  Code TOTP     : {code_now} (valable 30s)")
    print(f"  QR code       : http://localhost:5000/login-test")
    print("=" * 50)

# ============================================================
# MENU PRINCIPAL
# ============================================================

def afficher_menu_roles():
    print("\n  Rôles disponibles :")
    for i, role in enumerate(ROLES_DISPONIBLES, 1):
        print(
            f"    {i}. {role}"
            f"\n       → {DESCRIPTIONS_ROLES[role]}"
        )

def confirmer(question):
    """Demande une confirmation oui/non."""
    rep = input(f"  {question} (oui/non) : ").strip().lower()
    return rep == "oui"

def menu_principal():
    print("\n" + "=" * 50)
    print("  BMI — GESTION DES UTILISATEURS")
    print("  Compatible auth.py + app.py")
    print("=" * 50)

    while True:
        print("\n  MENU PRINCIPAL")
        print("  " + "-" * 30)
        print("  1. Ajouter un utilisateur")
        print("  2. Lister les utilisateurs")
        print("  3. Détails d'un utilisateur")
        print("  4. Désactiver un utilisateur")
        print("  5. Réactiver un utilisateur")
        print("  6. Réinitialiser le TOTP")
        print("  7. Changer le mot de passe")
        print("  8. Débloquer (reset échecs)")
        print("  9. Quitter")
        print("  " + "-" * 30)

        choix = input("  Votre choix (1-9) : ").strip()

        # ---- 1. AJOUTER ----
        if choix == "1":
            print("\n  --- AJOUTER UN UTILISATEUR ---")

            # Identifiant de connexion (username)
            print("  L'identifiant de connexion est l'adresse mail BMI de l'employé.")
            print("  Exemple : kofi@bmi.bj")
            while True:
                username = input("\n  Identifiant (ex: kofi@bmi.bj) : ").strip().lower()
                if not verifier_email(username):
                    print("  Format invalide. Utilisez le format prenom@bmi.bj")
                    continue
                if utilisateur_existe(username):
                    print(f"  '{username}' existe déjà en base.")
                    continue
                break

            # Adresse mail de réception (peut différer du username)
            print()
            print("  Email où envoyer les identifiants (ex: kofi.agbessi@bmi.bj)")
            print("  Laisser vide pour envoyer à l'identifiant ci-dessus.")
            email_input = input("  Email réception : ").strip().lower()
            if email_input and not verifier_email(email_input):
                print("  Format invalide — l'email de l'identifiant sera utilisé.")
                email_input = ""
            email_employe = email_input if email_input else username

            # Prénom / Nom pour la salutation dans le mail
            nom_affiche = input("  Prénom ou Nom complet (pour le mail) : ").strip()

            # Mot de passe — généré automatiquement
            print()
            print("  ℹ  Le mot de passe temporaire sera généré automatiquement.")
            print("     L'employé devra le changer à sa première connexion.")

            # Rôle
            print()
            afficher_menu_roles()
            while True:
                try:
                    idx = int(input(
                        f"\n  Rôle (1-{len(ROLES_DISPONIBLES)}) : "
                    ))
                    if 1 <= idx <= len(ROLES_DISPONIBLES):
                        role = ROLES_DISPONIBLES[idx - 1]
                        break
                    print("  Numéro invalide.")
                except ValueError:
                    print("  Entrez un numéro.")

            # Créer l'utilisateur
            secret = ajouter_utilisateur(
                username, None, role,
                email_employe=email_employe,
                nom_affiche=nom_affiche
            )

            if secret:
                totp = pyotp.TOTP(secret)
                print("\n  " + "=" * 48)
                print("  UTILISATEUR CRÉÉ AVEC SUCCÈS")
                print("  " + "=" * 48)
                print(f"  Email   : {username}")
                print(f"  Rôle    : {role}")
                print(f"  Code    : {totp.now()} (30s)")
                print()
                print("  Pour configurer Google Authenticator :")
                print(
                    "  → Ouvrir http://localhost:5000/login-test"
                )
                print(
                    "  → Scanner le QR code du compte"
                )
                print("  " + "=" * 48)

        # ---- 2. LISTER ----
        elif choix == "2":
            lister_utilisateurs()

        # ---- 3. DÉTAILS ----
        elif choix == "3":
            username = input("  Email : ").strip().lower()
            afficher_info_utilisateur(username)

        # ---- 4. DÉSACTIVER ----
        elif choix == "4":
            lister_utilisateurs()
            username = input(
                "\n  Email à désactiver : "
            ).strip().lower()

            if not utilisateur_existe(username):
                print(f"  '{username}' non trouvé.")
                continue

            if confirmer(f"Désactiver '{username}' ?"):
                if desactiver_utilisateur(username):
                    print(f"  '{username}' désactivé.")
                else:
                    print("  Erreur.")
            else:
                print("  Annulé.")

        # ---- 5. RÉACTIVER ----
        elif choix == "5":
            lister_utilisateurs()
            username = input(
                "\n  Email à réactiver : "
            ).strip().lower()

            if not utilisateur_existe(username):
                print(f"  '{username}' non trouvé.")
                continue

            if confirmer(f"Réactiver '{username}' ?"):
                if reactiver_utilisateur(username):
                    print(f"  '{username}' réactivé.")
                else:
                    print("  Erreur.")

        # ---- 6. RESET TOTP ----
        elif choix == "6":
            lister_utilisateurs()
            username = input(
                "\n  Email pour reset TOTP : "
            ).strip().lower()

            if not utilisateur_existe(username):
                print(f"  '{username}' non trouvé.")
                continue

            if confirmer(
                f"Générer nouveau TOTP pour '{username}' ?"
            ):
                nouveau_secret = reinitialiser_totp(username)
                if nouveau_secret:
                    totp = pyotp.TOTP(nouveau_secret)
                    print(f"  Nouveau secret : {nouveau_secret}")
                    print(f"  Code actuel   : {totp.now()}")
                    print(
                        "  → L'utilisateur doit rescanner "
                        "le QR sur /login-test"
                    )
                else:
                    print("  Erreur lors du reset.")

        # ---- 7. CHANGER MDP ----
        elif choix == "7":
            lister_utilisateurs()
            username = input("\n  Email : ").strip().lower()

            if not utilisateur_existe(username):
                print(f"  '{username}' non trouvé.")
                continue

            while True:
                nouveau = getpass.getpass(
                    "  Nouveau mot de passe (masqué) : "
                )
                confirmation = getpass.getpass(
                    "  Confirmer : "
                )
                if nouveau != confirmation:
                    print("  Ne correspondent pas.")
                    continue
                break

            ok, msg = changer_mot_de_passe(username, nouveau)
            print(f"  {'OK' if ok else 'ERREUR'} : {msg}")

        # ---- 8. DÉBLOQUER ----
        elif choix == "8":
            lister_utilisateurs()
            username = input(
                "\n  Email à débloquer : "
            ).strip().lower()

            if not utilisateur_existe(username):
                print(f"  '{username}' non trouvé.")
                continue

            reinitialiser_echecs(username)

        # ---- 9. QUITTER ----
        elif choix == "9":
            print("\n  Au revoir.")
            sys.exit(0)

        else:
            print("  Choix invalide (1-9).")

if __name__ == "__main__":
    menu_principal()
