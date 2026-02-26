from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.models.database import User, get_db
from app.utils.auth import verify_password, create_token

router = APIRouter(prefix="/auth", tags=["Authentification"])

@router.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()

    if not user or not verify_password(form.password, user.password):
        raise HTTPException(status_code=401, detail="Identifiants incorrects")

    if not user.active:
        raise HTTPException(status_code=403, detail="Compte désactivé")

    token = create_token(user.username, user.role)
    print(f"\n CONNEXION  |  {user.username} ({user.role})")
    return {
        "access_token": token,
        "token_type":   "bearer",
        "role":         user.role,
        "username":     user.username
    }
