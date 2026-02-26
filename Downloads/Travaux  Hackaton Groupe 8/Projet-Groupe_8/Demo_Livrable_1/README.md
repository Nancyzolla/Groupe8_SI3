================================================================================
  BMI AUTH v2.0 — Système d'authentification MFA pour l'usine GDIZ
  Bénin · Glo-Djigbé Industrial Zone
================================================================================

  Stack : Python 3.10+ · Flask · JWT RS256 · Argon2 · TOTP · SQLite · Waitress
  Auteur : Norberto
  Licence : Usage interne GDIZ

--------------------------------------------------------------------------------
  SOMMAIRE
--------------------------------------------------------------------------------

  1.  Présentation
  2.  Prérequis
  3.  Installation
  4.  Lancer le serveur
  5.  Premier accès — comptes de test
  6.  Gérer les utilisateurs
  7.  Configurer l'envoi de mail (optionnel)
  8.  Structure des fichiers
  9.  Base de données
  10. Commandes utiles
  11. Dépannage fréquent


================================================================================
  1. PRÉSENTATION
================================================================================

BMI Auth est un serveur d'authentification MFA complet développé en Python/Flask.
Il sécurise l'accès à la plateforme de maintenance prédictive de l'usine BMI.

Mécanismes implémentés :
  - Authentification 3 étapes : identifiants → QR Code TOTP → JWT
  - Tokens JWT RS256 asymétriques (15 min) + Refresh Token rotatif (7 jours)
  - Hashage Argon2id (résistant GPU/ASIC) avec compatibilité SHA-256
  - Changement de mot de passe forcé au premier login
  - Politique de mot de passe (complexité, historique, liste noire, score)
  - Anti brute-force 2 niveaux (application + IDS)
  - IDS 8 moteurs : brute-force, scan, DDoS, SQL injection, XSS,
    credential stuffing, path traversal, scanners connus
  - RBAC 4 rôles : operateur_fanuc / ingenieur_maintenance / administrateur / auditeur
  - Journalisation triple : auth_bmi.log + security.log + ids_bmi.log + SQLite
  - Envoi automatique des credentials par Gmail SMTP au premier login
  - Dashboard IDS en temps réel dans le terminal


================================================================================
  2. PRÉREQUIS
================================================================================

  Python 3.10 ou supérieur (obligatoire pour les f-strings et le typage utilisé)
  pip (gestionnaire de paquets Python)
  Connexion internet au premier lancement (pour pip install)
  Un smartphone avec Google Authenticator (iOS ou Android) pour le TOTP

  Systèmes testés :
    - Debian 12 / Ubuntu 22.04+ / Ubuntu 24.04
    - macOS 13+
    - Windows 10/11 (via cmd ou PowerShell — Git Bash recommandé)

  Pour l'envoi de mail (optionnel) :
    - Un compte Gmail
    - La validation en 2 étapes activée sur ce compte Gmail
    - Un "mot de passe d'application" Gmail (16 caractères)
      → Créer sur : https://myaccount.google.com/apppasswords


================================================================================
  3. INSTALLATION
================================================================================

  ── Étape 1 : Cloner ou copier le dossier ──────────────────────────────────

    git clone https://github.com/votre-compte/bmi_auth.git
    cd bmi_auth

    OU simplement copier le dossier bmi_auth sur votre machine.

  ── Étape 2 : Créer un environnement virtuel (recommandé) ──────────────────

    python3 -m venv venv

    Activer l'environnement :
      Linux / macOS :   source venv/bin/activate
      Windows cmd :     venv\Scripts\activate.bat
      Windows PowerShell : venv\Scripts\Activate.ps1

  ── Étape 3 : Installer les dépendances ────────────────────────────────────

    pip install flask
    pip install PyJWT
    pip install cryptography
    pip install pyotp
    pip install qrcode[pil]
    pip install argon2-cffi
    pip install waitress
    pip install rich

    OU en une seule commande si vous avez créé un requirements.txt :

    pip install flask PyJWT cryptography pyotp "qrcode[pil]" argon2-cffi waitress rich

  ── Vérification rapide ─────────────────────────────────────────────────────

    python3 -c "import flask, jwt, cryptography, pyotp, qrcode, argon2, waitress, rich; print('OK')"

    Résultat attendu : OK


================================================================================
  4. LANCER LE SERVEUR
================================================================================

  ── Mode production (recommandé) ───────────────────────────────────────────

    python serveur.py

    Waitress démarre avec 8 threads. Le serveur est accessible depuis
    n'importe quelle machine sur le même réseau local.

    À l'écran s'affichent :
      - Les comptes de test avec leurs mots de passe et codes TOTP actuels
      - L'adresse IP locale du serveur
      - Les URLs d'accès

    Exemple d'affichage :
      ═══════════════════════════════════════════════════════
        BMI AUTH — SERVEUR RÉSEAU
      ═══════════════════════════════════════════════════════
      
      ACCÈS RÉSEAU :
        Ce PC         : http://localhost:5000/login-page
        Autres PC     : http://192.168.x.x:5000/login-page
        API           : http://192.168.x.x:5000/

  ── Mode développement ─────────────────────────────────────────────────────

    python app.py

    Flask démarre en mode debug sur localhost:5000 uniquement.
    Rechargement automatique du code à chaque modification.
    NE PAS utiliser en production (mode debug = sécurité réduite).

  ── Arrêter le serveur ─────────────────────────────────────────────────────

    Ctrl + C dans le terminal où le serveur tourne.


================================================================================
  5. PREMIER ACCÈS — COMPTES DE TEST
================================================================================

  Ouvrir dans un navigateur : http://localhost:5000/login-page

  4 comptes de test sont créés automatiquement au premier démarrage :

  ┌─────────────────────┬──────────────────┬───────────────────────┐
  │ Email               │ Mot de passe     │ Rôle                  │
  ├─────────────────────┼──────────────────┼───────────────────────┤
  │ kofi@bmi.bj         │ MotDePasse123!   │ operateur_fanuc       │
  │ ingenieur@bmi.bj    │ Maintenance456!  │ ingenieur_maintenance │
  │ admin@bmi.bj        │ AdminBMI2026!    │ administrateur        │
  │ auditeur@bmi.bj     │ Audit789!        │ auditeur              │
  └─────────────────────┴──────────────────┴───────────────────────┘

  IMPORTANT — Comment utiliser le code TOTP :

    1. Installer Google Authenticator sur votre téléphone
       iOS  : https://apps.apple.com/app/google-authenticator/id388497605
       Android : https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2

    2. À l'étape 2 du login, un QR Code s'affiche dans le navigateur.
       Scanner ce QR Code avec Google Authenticator.
       → L'application ajoute automatiquement le compte "BMI_Usine_GDIZ".
       → Le QR disparaît après scan (comportement WhatsApp Web).

    3. Saisir le code à 6 chiffres affiché dans l'application.
       Le code change toutes les 30 secondes.

    NOTE : Les codes TOTP actuels s'affichent aussi dans le terminal au
    démarrage du serveur. Utile pour les tests sans téléphone.

    NOTE : Si vous recréez la base (suppression de bmi_auth.db), les secrets
    TOTP changent — il faut re-scanner les QR Codes dans Google Authenticator.


================================================================================
  6. GÉRER LES UTILISATEURS
================================================================================

    python ajouter_utilisateur.py

  Menu interactif avec 9 options :

    1. Ajouter un utilisateur
       → Saisir un email + choisir un rôle
       → Le mot de passe est généré automatiquement (12 caractères, fort)
       → Un email de bienvenue est envoyé si le mailer est configuré
       → Le mot de passe s'affiche dans le terminal (fallback)
       → L'utilisateur devra changer son mot de passe à la première connexion

    2. Lister les utilisateurs
       → Affiche tous les comptes avec leur rôle et statut

    3. Détails d'un utilisateur
       → Informations complètes : rôle, actif/inactif, must_change, TOTP secret

    4. Désactiver un utilisateur
       → Bloque l'accès sans supprimer le compte

    5. Réactiver un utilisateur
       → Rétablit l'accès d'un compte désactivé

    6. Réinitialiser le TOTP
       → Génère un nouveau secret TOTP (nouveau QR Code à scanner)

    7. Changer le mot de passe
       → Réinitialise le mot de passe d'un compte existant
       → Repositionne must_change=1 (nouvel accès forcé)

    8. Débloquer (reset échecs)
       → Libère un compte bloqué après trop de tentatives échouées

    9. Quitter

  Rôles disponibles :
    operateur_fanuc       → Accès FANUC_1, 2, 3 uniquement
    ingenieur_maintenance → Accès FANUC 1-12, KUKA 1-5, IFM/OMEGA/Siemens
    administrateur        → Accès total + gestion des logs
    auditeur              → Lecture des logs uniquement, pas de capteurs


================================================================================
  7. CONFIGURER L'ENVOI DE MAIL (OPTIONNEL)
================================================================================

  L'envoi de mail permet d'envoyer automatiquement les credentials par email
  à chaque nouveau compte créé. Si non configuré, le mot de passe s'affiche
  dans le terminal — rien ne bloque.

  ── Étape 1 : Créer un mot de passe d'application Gmail ───────────────────

    1. Aller sur : https://myaccount.google.com/security
    2. Activer la "Validation en 2 étapes" si ce n'est pas déjà fait
    3. Aller sur : https://myaccount.google.com/apppasswords
    4. Créer un mot de passe : "Autre (texte personnalisé)" → nommer "BMI Auth"
    5. Copier les 16 caractères générés (format : xxxx xxxx xxxx xxxx)

  ── Étape 2 : Configurer les variables d'environnement ────────────────────

    Linux / macOS :
      export BMI_GMAIL="votre.adresse@gmail.com"
      export BMI_GMAIL_PWD="xxxx xxxx xxxx xxxx"
      export BMI_URL="http://192.168.x.x:5000/login-page"
      export BMI_NOM="BMI Auth System"

    Windows cmd :
      set BMI_GMAIL=votre.adresse@gmail.com
      set BMI_GMAIL_PWD=xxxx xxxx xxxx xxxx
      set BMI_URL=http://192.168.x.x:5000/login-page

    Ou modifier directement les lignes 32-38 de mailer.py :
      GMAIL_EXPEDITEUR   = "votre.adresse@gmail.com"
      GMAIL_APP_PASSWORD = "xxxx xxxx xxxx xxxx"
      URL_SYSTEME        = "http://192.168.x.x:5000/login-page"

  ── Étape 3 : Tester l'envoi ───────────────────────────────────────────────

    python mailer.py

    Le script demande une adresse destinataire et envoie un mail de test
    avec des credentials fictifs. Vérifier la boîte de réception (et Spam).

  REMARQUE : Le mot de passe d'application Gmail est différent de votre
  vrai mot de passe Gmail. Il est révocable à tout moment depuis votre
  compte Google sans affecter votre compte principal.


================================================================================
  8. STRUCTURE DES FICHIERS
================================================================================

  bmi_auth/
  │
  ├── app.py                  Serveur Flask principal — routes API et middleware IDS
  ├── serveur.py              Lancement production avec Waitress (8 threads)
  │
  ├── auth.py                 Authentification MFA, JWT RS256, refresh tokens, brute-force
  ├── database.py             Initialisation SQLite, helpers CRUD, flags must_change
  ├── password_policy.py      Validation complexité, historique, liste noire, score 0-100
  ├── detecteur.py            IDS 8 moteurs, ban IP, alertes SQLite
  ├── logger_bmi.py           Loggers Python : auth_bmi.log, security.log, ids_bmi.log
  ├── mailer.py               Envoi Gmail SMTP TLS:587, template HTML, gestion erreurs
  │
  ├── ajouter_utilisateur.py  CLI admin — création et gestion des comptes
  ├── generer_qrcode.py       Génération des QR Codes PNG pour chaque utilisateur
  ├── migration.py            Migration SHA-256 → Argon2 (à lancer une seule fois)
  │
  ├── dashboard.py            Tableau de bord IDS Rich en temps réel (terminal séparé)
  ├── schema_jwt.py           Schéma visuel complet du système dans le terminal
  │
  ├── test_complet.py         Suite de 12 tests automatisés (lancer après app.py)
  ├── test_rapide.py          Test de connexion unique pour vérification rapide
  │
  ├── templates/
  │   └── login.html          Interface web — 3 étapes MFA + changement de mot de passe
  │
  ├── bmi_auth.db             Base SQLite (créée automatiquement au 1er démarrage)
  ├── auth_bmi.log            Journal des connexions et JWT (créé automatiquement)
  ├── security.log            Journal des événements de sécurité (créé automatiquement)
  └── ids_bmi.log             Journal des alertes IDS (créé automatiquement)

  FICHIERS CRÉÉS AUTOMATIQUEMENT — ne pas inclure dans Git :
    bmi_auth.db    (contient les mots de passe hashés et secrets TOTP)
    *.log          (journaux)

  Ajouter au .gitignore :
    bmi_auth.db
    *.log
    venv/
    __pycache__/
    *.pyc


================================================================================
  9. BASE DE DONNÉES
================================================================================

  Fichier : bmi_auth.db (SQLite, créé automatiquement)
  Supprimable pour repartir de zéro — sera recréé au prochain démarrage.

  Tables :
    users              Comptes utilisateurs (email, hash Argon2, secret TOTP, rôle, actif)
    refresh_tokens     Tokens de session longue (UUID, used, expires_at)
    auth_logs          Journal des connexions (username, IP, action, succès, timestamp)
    tentatives         Compteur anti brute-force par username+IP
    password_history   Historique des 5 derniers hashes pour éviter la réutilisation
    password_metadata  Flags must_change et expiration par utilisateur
    qr_scans           Tickets QR Code (scanne=0/1 pour le mécanisme WhatsApp)
    alertes_ids        Alertes IDS avec IP, moteur, sévérité, timestamp
    ip_bannies         IPs actuellement bannies avec raison et durée

  Inspecter la base :
    sqlite3 bmi_auth.db ".tables"
    sqlite3 bmi_auth.db "SELECT username, role, actif FROM users;"
    sqlite3 bmi_auth.db "SELECT username, must_change FROM password_metadata;"
    sqlite3 bmi_auth.db "SELECT * FROM ip_bannies;"


================================================================================
  10. COMMANDES UTILES
================================================================================

  ── Serveur ──────────────────────────────────────────────────────────────────

    python serveur.py                  # Production (Waitress, réseau local)
    python app.py                      # Développement (Flask debug, localhost)

  ── Administration ───────────────────────────────────────────────────────────

    python ajouter_utilisateur.py      # Gérer les comptes
    python generer_qrcode.py           # Générer les QR Codes PNG
    python migration.py                # Migrer SHA-256 → Argon2 (1 seule fois)

  ── Monitoring ───────────────────────────────────────────────────────────────

    python dashboard.py                # Tableau de bord IDS (terminal séparé)
    python schema_jwt.py               # Schéma complet du système
    tail -f auth_bmi.log               # Logs connexions en direct
    tail -f security.log               # Logs sécurité en direct
    tail -f ids_bmi.log                # Logs IDS en direct

  ── Tests ────────────────────────────────────────────────────────────────────

    python test_complet.py             # Suite 12 tests (serveur doit être lancé)
    python test_rapide.py              # Test connexion rapide
    python mailer.py                   # Tester l'envoi de mail

  ── Base de données ──────────────────────────────────────────────────────────

    sqlite3 bmi_auth.db "SELECT username, role, actif FROM users;"
    sqlite3 bmi_auth.db "SELECT * FROM auth_logs ORDER BY timestamp DESC LIMIT 20;"
    sqlite3 bmi_auth.db "SELECT * FROM ip_bannies;"
    sqlite3 bmi_auth.db "SELECT username, must_change FROM password_metadata;"
    sqlite3 bmi_auth.db "DELETE FROM ip_bannies;"   # Débloquer toutes les IP

  ── Repartir de zéro ─────────────────────────────────────────────────────────

    rm bmi_auth.db *.log               # Linux/macOS
    del bmi_auth.db *.log              # Windows
    python serveur.py                  # Recréer tout automatiquement

  ── URLs disponibles ─────────────────────────────────────────────────────────

    http://localhost:5000/login-page   # Interface de connexion
    http://localhost:5000/             # Status de l'API (JSON)
    http://localhost:5000/api/capteurs # Données capteurs (JWT requis)
    http://localhost:5000/api/logs     # Journaux (admin/auditeur uniquement)
    http://localhost:5000/refresh      # Renouveler le JWT (cookie requis)
    http://localhost:5000/change-password  # Changer le mot de passe (JWT requis)





================================================================================
  NOTE DE SÉCURITÉ
================================================================================

 

  NE PAS exposer ce serveur directement sur Internet sans :
    - Un reverse proxy HTTPS (Nginx, Caddy)
    - Un certificat TLS valide
    - Un filtrage réseau (firewall, whitelist IP)
    - Un audit de sécurité préalable

  Les clés RSA sont générées en RAM à chaque démarrage.

