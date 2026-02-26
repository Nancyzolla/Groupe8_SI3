"""
mailer.py — BMI Auth v2.0
Envoi d'emails via Gmail SMTP (internet).

═══════════════════════════════════════════════════════════
 CONFIGURATION GMAIL — UNE SEULE FOIS
═══════════════════════════════════════════════════════════
 Gmail n'accepte PAS votre vrai mot de passe ici.
 Il faut un "mot de passe d'application" (16 caractères).

 Étapes :
   1. Sur le compte Gmail expéditeur, activez la validation
      en 2 étapes si ce n'est pas déjà fait :
      → myaccount.google.com → Sécurité → Validation en 2 étapes

   2. Créez un mot de passe d'application :
      → myaccount.google.com/apppasswords
      → "Sélectionner l'application" : Autre (texte personnalisé)
      → Nommez-le "BMI Auth" → Générer
      → Copiez les 16 caractères affichés (format : xxxx xxxx xxxx xxxx)

   3. Renseignez ci-dessous ou via variables d'environnement :
      export BMI_GMAIL="votre.adresse@gmail.com"
      export BMI_GMAIL_PWD="xxxx xxxx xxxx xxxx"
      export BMI_URL="http://votre-ip:5000/login-page"

 Note de sécurité : ne commitez jamais ce fichier avec les
 vraies valeurs. Préférez les variables d'environnement.
═══════════════════════════════════════════════════════════
"""

import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from datetime             import datetime

# ============================================================
# CONFIGURATION
# ============================================================

GMAIL_EXPEDITEUR   = os.environ.get("BMI_GMAIL",     "CONFIGURER@gmail.com")
GMAIL_APP_PASSWORD = os.environ.get("BMI_GMAIL_PWD", "CONFIGURER")
NOM_EXPEDITEUR     = os.environ.get("BMI_NOM",       "BMI Auth System — GDIZ")
URL_SYSTEME        = os.environ.get("BMI_URL",        "http://192.168.100.43:5000/login-page")

SMTP_HOST    = "smtp.gmail.com"
SMTP_PORT    = 587
TIMEOUT      = 15  # secondes

# ============================================================
# VÉRIFICATION CONFIGURATION
# ============================================================

def _est_configure():
    return (
        GMAIL_EXPEDITEUR   != "CONFIGURER@gmail.com"
        and GMAIL_APP_PASSWORD != "CONFIGURER"
        and len(GMAIL_APP_PASSWORD.replace(" ", "")) == 16
    )

# ============================================================
# CONSTRUCTION DU MAIL
# ============================================================

def _construire_email(destinataire, username, mdp_temp, role, nom_affiche=""):
    descriptions_roles = {
        "operateur_fanuc":       "Opérateur CNC FANUC",
        "ingenieur_maintenance": "Ingénieur Maintenance",
        "administrateur":        "Administrateur Système",
        "auditeur":              "Auditeur",
    }
    role_affiche = descriptions_roles.get(role, role)
    date_envoi   = datetime.now().strftime("%d/%m/%Y à %H:%M")
    sujet        = "[BMI Auth] Vos accès au système — À lire immédiatement"

    # ── TEXTE BRUT ────────────────────────────────────────────
    salutation  = nom_affiche if nom_affiche else ""
    bonjour     = f"Bonjour {salutation}," if salutation else "Bonjour,"
    corps_texte = f"""{bonjour}

Votre compte d'accès au Système d'Authentification BMI / GDIZ a été créé.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  IDENTIFIANT   : {username}
  MOT DE PASSE  : {mdp_temp}
  RÔLE          : {role_affiche}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠  Ce mot de passe est TEMPORAIRE.
   Vous devrez le changer dès votre première connexion.
   Votre nouveau mot de passe ne sera connu que de vous.

Accéder au système :
  {URL_SYSTEME}

AUTHENTIFICATION EN 2 ÉTAPES OBLIGATOIRE :
  À la première connexion, un QR code s'affichera.
  Installez "Google Authenticator" sur votre téléphone
  et scannez-le pour activer votre code TOTP (6 chiffres / 30s).

CONSIGNES DE SÉCURITÉ :
  • Ne communiquez JAMAIS votre mot de passe
  • Ne transférez pas cet email
  • Changez votre mot de passe à la première connexion
  • Problème d'accès : contactez l'administrateur système

Envoyé le {date_envoi} — BMI Auth System / GDIZ, Bénin
Ce message est confidentiel et destiné uniquement à {destinataire}
""".strip()

    # ── VERSION HTML ──────────────────────────────────────────
    corps_html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BMI Auth — Vos accès</title>
</head>
<body style="margin:0;padding:0;background:#f0f4f8;
             font-family:Arial,Helvetica,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0"
       style="background:#f0f4f8;padding:32px 16px;">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0"
       style="background:#fff;border-radius:14px;overflow:hidden;
              box-shadow:0 4px 24px rgba(0,0,0,0.10);max-width:560px;">

  <!-- EN-TÊTE -->
  <tr>
    <td style="background:linear-gradient(135deg,#1e3a5f 0%,#2e75b6 100%);
               padding:32px 36px;text-align:center;">
      <div style="font-size:42px;margin-bottom:10px;">🔐</div>
      <div style="color:#fff;font-size:22px;font-weight:700;
                  letter-spacing:0.02em;">BMI Auth System</div>
      <div style="color:rgba(255,255,255,0.65);font-size:13px;
                  margin-top:5px;">GDIZ — Glo-Djigbé Industrial Zone, Bénin</div>
    </td>
  </tr>

  <!-- CORPS -->
  <tr><td style="padding:32px 36px;">

    <p style="color:#1e3a5f;font-size:16px;font-weight:700;margin:0 0 6px;">
      {bonjour}
    </p>
    <p style="color:#555;font-size:14px;line-height:1.7;margin:0 0 26px;">
      Votre compte d'accès au système de supervision sécurisé BMI a été créé
      par l'administrateur. Conservez ces informations en lieu sûr.
    </p>

    <!-- CARTE IDENTIFIANTS -->
    <table width="100%" cellpadding="0" cellspacing="0"
           style="background:#ebf2fa;border:1px solid #bee3f8;
                  border-radius:12px;margin-bottom:22px;">
      <tr><td style="padding:22px 26px;">
        <div style="font-size:11px;font-weight:700;color:#2e75b6;
                    text-transform:uppercase;letter-spacing:0.08em;
                    margin-bottom:16px;">Vos identifiants de connexion</div>
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td style="font-size:13px;color:#555;padding:6px 0;
                       width:140px;font-weight:600;">Identifiant</td>
            <td style="font-size:14px;color:#1e3a5f;
                       font-family:monospace;font-weight:700;">{username}</td>
          </tr>
          <tr>
            <td style="font-size:13px;color:#555;padding:6px 0;
                       font-weight:600;">Mot de passe</td>
            <td>
              <span style="display:inline-block;background:#1e3a5f;color:#fff;
                           font-family:monospace;font-size:17px;font-weight:700;
                           padding:5px 14px;border-radius:8px;
                           letter-spacing:0.1em;">{mdp_temp}</span>
            </td>
          </tr>
          <tr>
            <td style="font-size:13px;color:#555;padding:6px 0;
                       font-weight:600;">Rôle</td>
            <td style="font-size:13px;color:#1e3a5f;
                       font-weight:600;">{role_affiche}</td>
          </tr>
        </table>
      </td></tr>
    </table>

    <!-- ALERTE MOT DE PASSE TEMPORAIRE -->
    <table width="100%" cellpadding="0" cellspacing="0"
           style="background:#fff8e1;border-left:4px solid #f59e0b;
                  border-radius:0 10px 10px 0;margin-bottom:22px;">
      <tr><td style="padding:14px 20px;">
        <div style="font-size:13px;font-weight:700;color:#b45309;
                    margin-bottom:5px;">⚠  Mot de passe temporaire</div>
        <div style="font-size:13px;color:#78350f;line-height:1.6;">
          Ce mot de passe est <strong>temporaire</strong>.
          Dès votre première connexion, vous serez invité à le remplacer
          par un mot de passe personnel que
          <strong>seul vous connaîtrez</strong>.
        </div>
      </td></tr>
    </table>

    <!-- BOUTON CONNEXION -->
    <table width="100%" cellpadding="0" cellspacing="0"
           style="margin-bottom:26px;">
      <tr><td align="center">
        <a href="{URL_SYSTEME}"
           style="display:inline-block;
                  background:linear-gradient(135deg,#1e3a5f,#2e75b6);
                  color:#fff;text-decoration:none;font-size:15px;
                  font-weight:700;padding:15px 40px;border-radius:11px;">
          Accéder au système →
        </a>
        <div style="margin-top:10px;font-size:12px;color:#94a3b8;">
          {URL_SYSTEME}
        </div>
      </td></tr>
    </table>

    <!-- TOTP -->
    <table width="100%" cellpadding="0" cellspacing="0"
           style="background:#f0fdf4;border:1px solid #bbf7d0;
                  border-radius:12px;margin-bottom:22px;">
      <tr><td style="padding:18px 22px;">
        <div style="font-size:13px;font-weight:700;color:#166534;
                    margin-bottom:8px;">
          📱 Authentification en 2 étapes — OBLIGATOIRE
        </div>
        <div style="font-size:13px;color:#15803d;line-height:1.7;">
          Votre compte exige un <strong>code à 6 chiffres</strong>
          renouvelé toutes les 30 secondes.<br>
          Installez <strong>Google Authenticator</strong> sur votre
          téléphone, puis scannez le QR code affiché à la
          première connexion.
        </div>
        <div style="margin-top:12px;font-size:12px;color:#15803d;">
          → Recherchez <em>"Google Authenticator"</em>
          dans le Play Store (Android) ou l'App Store (iPhone)
        </div>
      </td></tr>
    </table>

    <!-- SÉCURITÉ -->
    <table width="100%" cellpadding="0" cellspacing="0"
           style="background:#fef2f2;border:1px solid #fecaca;
                  border-radius:12px;">
      <tr><td style="padding:16px 22px;">
        <div style="font-size:12px;font-weight:700;color:#991b1b;
                    margin-bottom:8px;">🔒 Consignes de sécurité</div>
        <ul style="margin:0;padding-left:18px;font-size:12px;
                   color:#7f1d1d;line-height:1.9;">
          <li>Ne communiquez <strong>jamais</strong> votre mot de passe,
              même à l'administrateur</li>
          <li>Ne transférez pas cet email</li>
          <li>Changez votre mot de passe dès la première connexion</li>
          <li>Verrouillez votre session si vous quittez votre poste</li>
          <li>Problème d'accès : contactez l'administrateur système</li>
        </ul>
      </td></tr>
    </table>

  </td></tr>

  <!-- PIED DE PAGE -->
  <tr>
    <td style="background:#f8fafc;border-top:1px solid #e2e8f0;
               padding:18px 36px;text-align:center;">
      <div style="font-size:11px;color:#94a3b8;line-height:1.7;">
        Envoyé automatiquement le {date_envoi}<br>
        BMI Auth System · GDIZ, Bénin<br>
        <strong>Message confidentiel</strong> — destiné uniquement à
        {destinataire}
      </div>
    </td>
  </tr>

</table>
</td></tr>
</table>
</body>
</html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = sujet
    msg["From"]    = f"{NOM_EXPEDITEUR} <{GMAIL_EXPEDITEUR}>"
    msg["To"]      = destinataire

    msg.attach(MIMEText(corps_texte, "plain", "utf-8"))
    msg.attach(MIMEText(corps_html,  "html",  "utf-8"))
    return msg


# ============================================================
# ENVOI GMAIL
# ============================================================

def envoyer_credentials(destinataire, username, mdp_temp, role, nom_affiche=""):
    """
    Envoie le mail de bienvenue avec les identifiants temporaires.

    Paramètres :
      destinataire → adresse email de l'employé
      username     → identifiant BMI (= destinataire dans ce projet)
      mdp_temp     → mot de passe temporaire généré
      role         → rôle attribué

    Retourne : (True, "") si succès, (False, message_erreur) sinon.
    """
    if not _est_configure():
        return False, (
            "Gmail non configuré.\n"
            "Renseignez BMI_GMAIL et BMI_GMAIL_PWD :\n"
            "  export BMI_GMAIL='votre.adresse@gmail.com'\n"
            "  export BMI_GMAIL_PWD='xxxx xxxx xxxx xxxx'"
        )

    try:
        msg = _construire_email(destinataire, username, mdp_temp, role, nom_affiche)

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=TIMEOUT) as srv:
            srv.ehlo()
            srv.starttls()
            srv.ehlo()
            srv.login(GMAIL_EXPEDITEUR, GMAIL_APP_PASSWORD)
            srv.sendmail(GMAIL_EXPEDITEUR, destinataire, msg.as_string())

        return True, ""

    except smtplib.SMTPAuthenticationError:
        return False, (
            "Authentification Gmail refusée.\n"
            "Causes possibles :\n"
            "  1. Vous avez saisi votre vrai mot de passe Gmail au lieu\n"
            "     d'un mot de passe d'APPLICATION (16 caractères).\n"
            "  2. La validation en 2 étapes n'est pas activée sur le compte.\n"
            "  3. L'accès aux applications moins sécurisées est désactivé.\n"
            "Solution : myaccount.google.com/apppasswords"
        )
    except smtplib.SMTPRecipientsRefused:
        return False, (
            f"Adresse email refusée : {destinataire}\n"
            "Vérifiez que l'adresse est valide."
        )
    except smtplib.SMTPConnectError:
        return False, (
            "Impossible de se connecter à smtp.gmail.com:587.\n"
            "Vérifiez la connexion internet du serveur."
        )
    except TimeoutError:
        return False, (
            f"Timeout ({TIMEOUT}s) — Gmail ne répond pas.\n"
            "Vérifiez la connexion internet."
        )
    except smtplib.SMTPException as e:
        return False, f"Erreur SMTP : {e}"
    except Exception as e:
        return False, f"Erreur inattendue : {e}"


# ============================================================
# TEST DE CONNEXION (sans envoyer de mail)
# ============================================================

def tester_connexion():
    """
    Vérifie que Gmail est joignable et que les identifiants
    sont valides. Ne pas envoyer de mail.
    Retourne (True, info) ou (False, erreur).
    """
    if not _est_configure():
        return False, "Gmail non configuré (voir variables d'environnement)."
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=TIMEOUT) as srv:
            srv.ehlo()
            srv.starttls()
            srv.ehlo()
            srv.login(GMAIL_EXPEDITEUR, GMAIL_APP_PASSWORD)
        return True, f"Connexion Gmail OK ({GMAIL_EXPEDITEUR})"
    except smtplib.SMTPAuthenticationError:
        return False, "Authentification échouée — vérifiez le mot de passe d'application."
    except Exception as e:
        return False, f"Connexion impossible : {e}"


# ============================================================
# TEST DIRECT EN LIGNE DE COMMANDE
# ============================================================

if __name__ == "__main__":
    print("=" * 55)
    print("  TEST MAILER — BMI Auth (Gmail)")
    print("=" * 55)
    print(f"  Expéditeur : {GMAIL_EXPEDITEUR}")
    print(f"  Configuré  : {'✅ Oui' if _est_configure() else '❌ Non'}")
    print()

    if not _est_configure():
        print("  ❌ Gmail non configuré.")
        print()
        print("  Renseignez les variables d'environnement :")
        print("    export BMI_GMAIL='votre.adresse@gmail.com'")
        print("    export BMI_GMAIL_PWD='xxxx xxxx xxxx xxxx'")
        print()
        print("  Ou modifiez directement mailer.py :")
        print("    GMAIL_EXPEDITEUR   = 'votre.adresse@gmail.com'")
        print("    GMAIL_APP_PASSWORD = 'xxxx xxxx xxxx xxxx'")
        exit(1)

    # Test de connexion
    print("  Test de connexion à smtp.gmail.com:587...")
    ok, info = tester_connexion()
    print(f"  {'✅' if ok else '❌'}  {info}")
    if not ok:
        exit(1)

    print()
    dest = input("  Email destinataire (pour le test) : ").strip()
    if not dest:
        print("  Annulé.")
        exit()

    print(f"\n  Envoi vers {dest}...")
    ok, err = envoyer_credentials(
        destinataire = dest,
        username     = "kofi@bmi.bj",
        mdp_temp     = "Kp7@nBx3!fR2",
        role         = "operateur_fanuc",
    )

    if ok:
        print(f"\n  ✅  Mail de test envoyé à {dest}")
        print("  Vérifiez la boîte mail (et le dossier Spam).")
    else:
        print(f"\n  ❌  Échec :")
        for ligne in err.split("\n"):
            print(f"     {ligne}")
