from flask import Flask, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configuration du Rate Limiter (Bouclier contre l'extraction)
# On limite à 5 requêtes par minute pour la démo
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "5 per minute"],
    storage_uri="memory://",
)

@app.route('/predict/schuler', methods=['GET'])
@limiter.limit("5 per minute") # Limite spécifique pour l'extraction de modèle
def predict():
    # Simulation d'une réponse du modèle IA (Random Forest/LSTM)
    return jsonify({
        "machine": "Presse SCHULER",
        "statut": "Optimal",
        "probabilite_panne": "2.4%",
        "conseil": "Maintenance dans 15 jours"
    })

if __name__ == '__main__':
    print("--- SERVEUR BMI : API de Prédiction Sécurisée ---")
    app.run(host='0.0.0.0', port=5000)
