import requests
import time

url = "http://127.0.0.1:5000/predict/schuler"

print("--- DÉBUT DE L'ATTAQUE PAR EXTRACTION DE MODÈLE ---")

for i in range(1, 11): # On tente 10 requêtes rapides
    response = requests.get(url)
    if response.status_code == 200:
        print(f"Requête {i}: Succès (Donnée extraite)")
    elif response.status_code == 429:
        print(f"Requête {i}: BLOQUÉE PAR LE RATE LIMITER (HTTP 429)")
    else:
        print(f"Requête {i}: Erreur {response.status_code}")
    time.sleep(0.5) # Attaque rapide
