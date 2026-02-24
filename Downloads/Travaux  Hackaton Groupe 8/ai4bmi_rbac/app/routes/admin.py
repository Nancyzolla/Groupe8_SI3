from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.models.database import User, AuditLog, get_db
from app.utils.auth import hash_password, decode_token

router = APIRouter(prefix="/admin", tags=["Administration"])

class UserCreate(BaseModel):
    username: str
    password: str
    role: str

class UserUpdate(BaseModel):
    role: str

def admin_only(token_data: dict = Depends(decode_token)):
    if token_data["role"] != "admin":
        raise HTTPException(status_code=403, detail="Réservé aux administrateurs")
    return token_data

@router.get("/", response_class=HTMLResponse)
def admin_page():
    with open("templates/admin.html", "r", encoding="utf-8") as f:
        return f.read()

@router.get("/users-list")
def list_users(db: Session = Depends(get_db), _=Depends(admin_only)):
    users = db.query(User).all()
    return {"users": [
        {"id": u.id, "username": u.username, "role": u.role, "active": u.active}
        for u in users
    ]}

@router.post("/users-add")
def add_user(data: UserCreate, db: Session = Depends(get_db), _=Depends(admin_only)):
    existing = db.query(User).filter(User.username == data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Utilisateur déjà existant")
    user = User(username=data.username, password=hash_password(data.password), role=data.role)
    db.add(user)
    db.commit()
    return {"message": f"Utilisateur {data.username} créé"}

@router.put("/users-update/{user_id}")
def update_user(user_id: int, data: UserUpdate, db: Session = Depends(get_db), _=Depends(admin_only)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    user.role = data.role
    db.commit()
    return {"message": "Rôle mis à jour"}

@router.delete("/users-delete/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), _=Depends(admin_only)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    db.delete(user)
    db.commit()
    return {"message": "Utilisateur supprimé"}

@router.get("/logs")
def get_logs(db: Session = Depends(get_db), _=Depends(admin_only)):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp).all()
    return {"logs": [
        {"timestamp": str(l.timestamp), "username": l.username, "role": l.role,
         "ip": l.ip, "resource": l.resource, "action": l.action, "status": l.status}
        for l in logs
    ]}
