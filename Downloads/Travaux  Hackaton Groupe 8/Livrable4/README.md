📝 Description du Projet

Ce projet implémente des mécanismes de défense avancés pour protéger l'infrastructure d'Intelligence Artificielle de l'usine Benin Moto Industry (BMI). Nous nous concentrons sur la sécurité des systèmes de maintenance prédictive des presses SCHULER et des robots KUKA.

Le travail est divisé en trois scénarios de protection contre les menaces spécifiques à l'IA.
🛡️ Scénarios de Sécurité Implémentés
1. [S1] Détection d'Empoisonnement (Data Poisoning)

    Objectif : Empêcher l'injection de fausses données de capteurs qui pourraient fausser les prédictions de panne.

    Solution : Utilisation de l'algorithme Isolation Forest pour filtrer et rejeter les anomalies thermiques en temps réel.

    Scripts : plateforme_centrale.py (Défense) et generateur_capteurs.py (Attaque).

2. [S2] Protection contre l'Extraction (Model Stealing)

    Objectif : Empêcher un concurrent de copier la logique du modèle via des requêtes API massives.

    Solution : Mise en œuvre d'un Rate Limiter (Limitation de débit) qui bloque les utilisateurs dépassant le quota de requêtes autorisé (Erreur HTTP 429).

    Scripts : serveur_bmi_s2.py (API) et attaque_extraction.py (Simulation d'attaque).

3. [S5] Confidentialité Différentielle (Inference Attack)

    Objectif : Empêcher la fuite de données stratégiques (cadences de production) via l'analyse des résultats de l'IA.

    Solution : Ajout d'un bruit gaussien aux sorties du modèle via la bibliothèque Diffprivlib (IBM).

    Script : defense_inference_s5.py.

🚀 Guide d'Exécution (Procédure venv)

1. Préparation de l'environnement

Ouvrez un terminal dans le dossier du projet :
Bash

# Créer et activer l'environnement
python3 -m venv venv_bmi
source venv_bmi/bin/activate

# Installer les dépendances
pip install flask flask-limiter diffprivlib pandas scikit-learn requests

2. Lancement des simulations

    Note : L'environnement venv_bmi doit être activé (source venv_bmi/bin/activate) dans chaque nouveau terminal.

🛠 Scénario 1 : Détection d'Empoisonnement

Ce test montre comment l'IA filtre les fausses données de température injectées par un capteur compromis.

    Terminal 1 : python3 plateforme_centrale.py

    (Lance le moniteur de sécurité basé sur Isolation Forest)

    Terminal 2 : python3 generateur_capteurs.py

    (Simule l'envoi de données saines et de données empoisonnées)

    Résultat attendu : La console affiche "⚠️ ANOMALIE DÉTECTÉE" pour chaque tentative d'empoisonnement.

🛠 Scénario 2 : Protection contre l'Extraction

Ce test valide le blocage des tentatives de vol du modèle par requêtes massives.

    Terminal 1 : python3 serveur_bmi_s2.py

    (Lance l'API sécurisée avec Rate Limiting)

    Terminal 2 : python3 attaque_extraction.py

    (Lance le script d'attaque automatisé)

    Résultat attendu : Les premières requêtes réussissent, puis le serveur renvoie l'erreur 429 Too Many Requests.

🛠 Scénario 5 : Confidentialité Différentielle

Ce test démontre la protection des secrets industriels (cadences de production).

    Terminal Unique : python3 defense_inference_s5.py

    Résultat attendu : Le script affiche la valeur réelle et la valeur "bruitée" envoyée à l'extérieur. On constate que la valeur bruitée change à chaque fois pour tromper un espion éventuel.

📂 Rappel de la structure des scripts
Script	Rôle technique
S1 : plateforme_centrale.py	Modèle Isolation Forest qui analyse les flux entrants.
S1 : generateur_capteurs.py	Simulateur de trafic capteur avec injection de bruits malveillants.
S2 : serveur_bmi_s2.py	API Flask protégée par Flask-Limiter.
S5 : defense_inference_s5.py	Implémentation du mécanisme Gaussien de Diffprivlib.
