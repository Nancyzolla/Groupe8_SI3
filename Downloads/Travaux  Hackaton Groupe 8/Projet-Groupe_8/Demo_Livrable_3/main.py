from fastapi import FastAPI
from contextlib import asynccontextmanager
from app.models.database import init_db, SessionLocal, User
from app.utils.auth import hash_password
from app.routes import auth, api, admin

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed_users()
    yield

def seed_users():
    """Créer les 4 utilisateurs de démonstration."""
    db = SessionLocal()
    if db.query(User).count() == 0:
        users = [
            User(username="alice",   password=hash_password("Admin2026"),  role="admin"),
            User(username="bob",     password=hash_password("Maint2026"),  role="ingenieur_maintenance"),
            User(username="charlie", password=hash_password("Oper2026"),   role="operateur"),
            User(username="diana",   password=hash_password("Audit2026"),  role="auditeur"),
        ]
        db.add_all(users)
        db.commit()
        print("\n Utilisateurs créés : alice (admin) | bob (ingénieur) | charlie (opérateur) | diana (auditeur)")
    db.close()

app = FastAPI(
    title="AI4BMI — Système RBAC",
    description="Contrôle d'accès basé sur les rôles pour la plateforme de maintenance prédictive BMI",
    version="1.0.0",
    lifespan=lifespan
)

app.include_router(auth.router)
app.include_router(api.router)
app.include_router(admin.router)

@app.get("/", tags=["Accueil"])
def root():
    return {
        "projet":  "AI4BMI — Hackathon IFRI",
        "module":  "L3 — Contrôle d'accès RBAC",
        "version": "1.0.0",
        "docs":    "/docs",
        "admin":   "/admin"
    }
