"""

"""

import re
import hashlib
from database import get_connection

POLITIQUE = {
    "longueur_min": 8,
    "longueur_max": 64,
    "requiert_majuscule": True,
    "requiert_minuscule": True,
    "requiert_chiffre": True,
    "requiert_special": True,
    "caracteres_speciaux": "!@#$%^&*()_+-=[]{}|;:,.<>?",
    "historique_max": 5,
    "expiration_jours": 90,
}

MOTS_DE_PASSE_INTERDITS = [
    "password", "123456", "azerty", "qwerty",
    "admin123", "bmi2026", "motdepasse",
    "Password1!", "Admin123!", "Bmi2026!",
]

def verifier_longueur(mot_de_passe):
    if len(mot_de_passe) < POLITIQUE["longueur_min"]:
        return False, f"Minimum {POLITIQUE['longueur_min']} caractères"
    if len(mot_de_passe) > POLITIQUE["longueur_max"]:
        return False, f"Maximum {POLITIQUE['longueur_max']} caractères"
    return True, ""

def verifier_complexite(mot_de_passe):
    erreurs = []
    if POLITIQUE["requiert_majuscule"] and \
       not re.search(r"[A-Z]", mot_de_passe):
        erreurs.append("une MAJUSCULE requise")
    if POLITIQUE["requiert_minuscule"] and \
       not re.search(r"[a-z]", mot_de_passe):
        erreurs.append("une minuscule requise")
    if POLITIQUE["requiert_chiffre"] and \
       not re.search(r"\d", mot_de_passe):
        erreurs.append("un chiffre requis")
    if POLITIQUE["requiert_special"]:
        speciaux = POLITIQUE["caracteres_speciaux"]
        if not any(c in speciaux for c in mot_de_passe):
            erreurs.append("un caractère spécial requis")
    if erreurs:
        return False, " | ".join(erreurs)
    return True, ""

def verifier_liste_noire(mot_de_passe):
    for interdit in MOTS_DE_PASSE_INTERDITS:
        if mot_de_passe.lower() == interdit.lower():
            return False, "Mot de passe trop courant"
    return True, ""

def verifier_historique(username, mot_de_passe):
    password_hash = hashlib.sha256(
        mot_de_passe.encode()
    ).hexdigest()

    conn = get_connection()
    cursor = conn.execute("""
        SELECT password_hash FROM password_history
        WHERE username = ?
        ORDER BY created_at DESC
        LIMIT ?
    """, (username, POLITIQUE["historique_max"]))

    historique = [row[0] for row in cursor.fetchall()]
    conn.close()

    if password_hash in historique:
        return False, "Mot de passe déjà utilisé récemment"
    return True, ""

def calculer_force(mot_de_passe):
    score = 0
    if len(mot_de_passe) >= 8:  score += 20
    if len(mot_de_passe) >= 12: score += 10
    if len(mot_de_passe) >= 16: score += 10
    if re.search(r"[A-Z]", mot_de_passe): score += 15
    if re.search(r"[a-z]", mot_de_passe): score += 15
    if re.search(r"\d", mot_de_passe):    score += 15
    speciaux = POLITIQUE["caracteres_speciaux"]
    if any(c in speciaux for c in mot_de_passe): score += 15

    if score >= 80:   niveau = "Fort"
    elif score >= 50: niveau = "Moyen"
    else:             niveau = "Faible"

    return score, niveau

def valider_mot_de_passe(mot_de_passe, username=None):
    erreurs = []
    checks = [
        verifier_longueur(mot_de_passe),
        verifier_complexite(mot_de_passe),
        verifier_liste_noire(mot_de_passe),
    ]
    if username:
        checks.append(verifier_historique(username, mot_de_passe))

    for valide, message in checks:
        if not valide:
            erreurs.append(message)

    score, niveau = calculer_force(mot_de_passe)
    return len(erreurs) == 0, erreurs, score, niveau

def sauvegarder_mot_de_passe(username, mot_de_passe):
    password_hash = hashlib.sha256(
        mot_de_passe.encode()
    ).hexdigest()
    conn = get_connection()
    conn.execute("""
        INSERT INTO password_history (username, password_hash)
        VALUES (?, ?)
    """, (username, password_hash))
    conn.execute("""
        INSERT OR REPLACE INTO password_metadata
        (username, last_changed)
        VALUES (?, CURRENT_TIMESTAMP)
    """, (username,))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    print("=" * 50)
    print("  POLITIQUE MOT DE PASSE — BMI")
    print("=" * 50)

    tests = [
        ("kofi@bmi.bj", "abc",             "Trop court"),
        ("kofi@bmi.bj", "password",        "Liste noire"),
        ("kofi@bmi.bj", "motdepasselong",  "Sans majuscule/chiffre"),
        ("kofi@bmi.bj", "MotDePasse123",   "Sans caractère spécial"),
        ("kofi@bmi.bj", "MotDePasse123!",  "Valide"),
        ("kofi@bmi.bj", "BMI@Secure2026#", "Très fort"),
    ]

    for username, mdp, description in tests:
        valide, erreurs, score, niveau = valider_mot_de_passe(
            mdp, username
        )
        statut = "OK" if valide else "KO"
        print(f"\n[{statut}] '{mdp}' — {description}")
        print(f"     Force : {score}/100 ({niveau})")
        if erreurs:
            for e in erreurs:
                print(f"     Erreur : {e}")
