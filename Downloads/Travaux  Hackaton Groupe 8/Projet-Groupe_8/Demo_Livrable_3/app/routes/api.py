from fastapi import APIRouter, Depends
from app.middleware.rbac import require_permission

router = APIRouter(prefix="/api", tags=["API BMI"])

@router.get("/capteurs",
    dependencies=[Depends(require_permission("capteurs", "read"))],
    summary="Lire les données capteurs IFM/OMEGA")
def get_capteurs():
    return {"data": [
        {"capteur": "IFM-VTV122-01",     "machine": "KUKA-KR210-1",  "vibration_hz": 45.2, "statut": "normal"},
        {"capteur": "OMEGA-OS-MINI-03",  "machine": "CNC-FANUC-3",   "temperature_c": 78.5, "statut": "elevee"},
        {"capteur": "SIEMENS-SITRANS-02","machine": "PRESSE-SCH-2",  "courant_A": 12.3,    "statut": "normal"},
    ]}

@router.get("/historiques",
    dependencies=[Depends(require_permission("historiques", "read"))],
    summary="Historiques de maintenance (sensible - S3)")
def get_historiques():
    return {"data": [
        {"id": 1, "machine": "KUKA-KR210-2", "panne": "roulement use",     "date": "2025-11-12", "piece": "SKF 6205"},
        {"id": 2, "machine": "CNC-FANUC-7",  "panne": "surchauffe broche", "date": "2025-12-03", "piece": "roulement NTN"},
    ]}

@router.get("/predictions",
    dependencies=[Depends(require_permission("predictions", "read"))],
    summary="Predictions de pannes (modele LSTM)")
def get_predictions():
    return {"data": [
        {"machine": "KUKA-KR210-1", "probabilite_panne": 0.87, "horizon": "72h", "action": "intervention urgente"},
        {"machine": "PRESSE-SCH-3", "probabilite_panne": 0.34, "horizon": "15j", "action": "surveillance"},
    ]}

@router.get("/admin/users",
    dependencies=[Depends(require_permission("admin_panel", "read"))],
    summary="Liste des utilisateurs (admin uniquement - S3)")
def get_users():
    return {"users": [
        {"username": "alice",   "role": "admin"},
        {"username": "bob",     "role": "ingenieur_maintenance"},
        {"username": "charlie", "role": "operateur"},
        {"username": "diana",   "role": "auditeur"},
    ]}

@router.get("/export",
    dependencies=[Depends(require_permission("export", "read"))],
    summary="Export donnees sensibles (admin/ingenieur - S3)")
def export_data():
    return {"message": "Export autorise", "records": 1547}

@router.get("/audit-logs",
    dependencies=[Depends(require_permission("audit_logs", "read"))],
    summary="Journaux d acces complets")
def get_audit_logs():
    return {"message": "Acces aux logs autorise"}
