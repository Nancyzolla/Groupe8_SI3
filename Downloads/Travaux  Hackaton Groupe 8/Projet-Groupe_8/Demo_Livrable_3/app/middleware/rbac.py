import casbin
import logging
import json
from datetime import datetime
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from app.utils.auth import decode_token
from app.models.database import AuditLog, get_db

enforcer = casbin.Enforcer('config/model.conf', 'config/policy.csv')

logging.basicConfig(
    filename='logs/audit.log',
    level=logging.INFO,
    format='%(message)s'
)
audit_logger = logging.getLogger("audit")

def log_access(db: Session, username: str, role: str, ip: str,
               resource: str, action: str, status: str, endpoint: str):
    log_entry = AuditLog(
        username=username, role=role, ip=ip,
        resource=resource, action=action,
        status=status, endpoint=endpoint
    )
    db.add(log_entry)
    db.commit()

    audit_logger.info(json.dumps({
        "timestamp": datetime.utcnow().isoformat(),
        "username":  username,
        "role":      role,
        "ip":        ip,
        "resource":  resource,
        "action":    action,
        "status":    status,
        "endpoint":  endpoint
    }))

def require_permission(resource: str, action: str):
    def dependency(
        request: Request,
        token_data: dict = Depends(decode_token),
        db: Session = Depends(get_db)
    ):
        username = token_data["username"]
        role     = token_data["role"]
        ip       = request.client.host if request.client else "unknown"
        endpoint = str(request.url.path)

        allowed = enforcer.enforce(username, resource, action)

        log_access(db, username, role, ip, resource, action,
                   "ALLOWED" if allowed else "DENIED", endpoint)

        if not allowed:
            print(f"\n ACCES REFUSE  |  {username} ({role})  ->  {resource}:{action}  |  IP: {ip}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error":    "Accès refusé",
                    "user":     username,
                    "role":     role,
                    "resource": resource,
                    "action":   action,
                    "message":  f"Le rôle '{role}' n'est pas autorisé à effectuer '{action}' sur '{resource}'"
                }
            )

        print(f"\n ACCES AUTORISE | {username} ({role})  ->  {resource}:{action}  |  IP: {ip}")
        return token_data

    return dependency
