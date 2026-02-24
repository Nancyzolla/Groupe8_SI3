import numpy as np
from diffprivlib.mechanisms import Gaussian

# Valeur réelle de la production stratégique (95%)
cadence_reelle = 0.95 

def obtenir_cadence_securisee(valeur):
    # Ajout d'un bruit différentiel (mécanisme Gaussien)
    # epsilon bas = plus de protection / epsilon haut = plus de précision
    dp_mechanism = Gaussian(epsilon=0.1, delta=0.01, sensitivity=0.05)
    return dp_mechanism.randomise(valeur)

print(f"--- SYSTÈME DE PROTECTION BMI (S5) ---")
print(f"Valeur brute (Confidentielle) : {cadence_reelle * 100}%")
print(f"Valeur envoyée à l'API (Bruitée) : {round(obtenir_cadence_securisee(cadence_reelle) * 100, 2)}%")
