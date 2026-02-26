# AI4BMI — Système RBAC
## Hackathon IFRI/UAC — Sécurité Informatique — Livrable L3

### Démarrage rapide

```bash
# 1. Créer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Lancer le serveur
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Accès
- Interface Admin : http://localhost:8000/admin
- Documentation API : http://localhost:8000/docs

### Comptes de démonstration
| Utilisateur | Mot de passe | Rôle |
|-------------|--------------|------|
| alice | Admin2026 | admin |
| bob | Maint2026 | ingenieur_maintenance |
| charlie | Oper2026 | operateur |
| diana | Audit2026 | auditeur |

### Structure
```
ai4bmi_rbac/
├── config/
│   ├── model.conf       # Modèle RBAC Casbin
│   └── policy.csv       # Règles de permissions
├── app/
│   ├── models/database.py    # Base de données SQLite
│   ├── middleware/rbac.py    # Moteur RBAC + Audit Trail
│   ├── utils/auth.py         # JWT Authentication
│   └── routes/
│       ├── auth.py           # Login
│       ├── api.py            # Routes protégées
│       └── admin.py          # Interface admin CRUD
├── templates/
│   └── admin.html       # Interface graphique
├── tests/
│   └── test_casbin.py   # Tests de la politique RBAC
├── logs/
│   └── audit.log        # Journal des accès
├── main.py              # Point d'entrée
└── requirements.txt     # Dépendances
```

### Scénarios couverts
- **S3** : Fuite de données — blocage accès non autorisés
- **S5** : Attaque par inférence — contrôle API par rôle
