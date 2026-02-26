import socket
import time
import random

SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999

def envoyer_donnee(valeur):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_IP, SERVER_PORT))
        s.send(str(valeur).encode())
        print(f"[SENT] Température envoyée : {valeur}°C")
        s.close()
    except Exception as e:
        print(f"[ERREUR] Connexion au serveur impossible : {e}")

print("--- GÉNÉRATEUR DE TEST BMI (S1) ---")

try:
    while True:
        # Envoi d'une donnée normale
        temp_normale = round(random.uniform(40.0, 60.0), 2)
        envoyer_donnee(temp_normale)
        time.sleep(2)

except KeyboardInterrupt:
    print("\nSimulation arrêtée.")
