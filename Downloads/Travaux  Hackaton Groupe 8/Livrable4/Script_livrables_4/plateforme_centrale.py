import socket
import numpy as np
from sklearn.ensemble import IsolationForest

# 1. Entraînement du bouclier (Isolation Forest)
historique_sain = np.random.uniform(40, 60, (100, 1))
bouclier = IsolationForest(contamination=0.1).fit(historique_sain)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', 9999))
server.listen(5)

print("--- PLATEFORME BMI : Surveillance active (Port 9999) ---")

while True:
    client, addr = server.accept()
    try:
        message = client.recv(1024).decode().strip()
        if message:
            # Nettoyage et conversion en nombre
            valeur = float(message)

            prediction = bouclier.predict([[valeur]])
            if prediction[0] == 1:
                print(f"[OK] {addr[0]} : {valeur}°C. Donnée acceptée.")
            else:
                print(f"[ALERTE S1] {addr[0]} : {valeur}°C. EMPOISONNEMENT DÉTECTÉ !")
    except ValueError:
        print(f"[ERREUR] Donnée non numérique reçue de {addr[0]}")
    except Exception as e:
        print(f"Erreur : {e}")
    finally:
        client.close()
