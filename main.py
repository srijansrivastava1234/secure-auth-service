from fastapi import FastAPI, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from datetime import timedelta
from typing import List

import models
import schemas
import security
from database import engine, get_db

# Auto-create all tables (Users and Audit Logs) in SQLite
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Secure Identity & RBAC Microservice",
    version="1.0.0",
    description="Enterprise Authentication, Role-Based Access Control, and Security Event Audit Logging"
)

# 1. Public Health Check
@app.get("/api/v1/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": "secure-identity-service",
        "version": "1.0.0",
        "database": "sqlite-connected"
    }

# 2. Public Registration
@app.post(
    "/api/v1/auth/register", 
    response_model=schemas.UserResponse, 
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"]
)
def register_user(user_in: schemas.UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter(models.User.email == user_in.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email address already exists."
        )

    hashed_pwd = security.hash_password(user_in.password)
    new_user = models.User(
        email=user_in.email,
        hashed_password=hashed_pwd,
        role=user_in.role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# 3. Public Login with Automated Security Audit Logging
@app.post(
    "/api/v1/auth/login", 
    response_model=schemas.Token,
    tags=["Authentication"]
)
def login_user(user_credentials: schemas.UserLogin, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    user = db.query(models.User).filter(models.User.email == user_credentials.email).first()

    # If user does not exist or password hash mismatch
    if not user or not security.verify_password(user_credentials.password, user.hashed_password):
        failed_log = models.AuditLog(
            event_type="LOGIN_FAILED",
            email=user_credentials.email,
            ip_address=client_ip
        )
        db.add(failed_log)
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Record Security Success in Audit Logs
    success_log = models.AuditLog(
        event_type="LOGIN_SUCCESS",
        email=user.email,
        ip_address=client_ip
    )
    db.add(success_log)
    db.commit()

    # Generate Signed JWT Access Token
    access_token_expires = timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.email, "user_id": user.id, "role": user.role.value},
        expires_delta=access_token_expires
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in_minutes": security.ACCESS_TOKEN_EXPIRE_MINUTES
    }

# 4. Protected User Profile
@app.get(
    "/api/v1/users/me", 
    response_model=schemas.UserResponse,
    tags=["Users"]
)
def get_current_user_profile(current_user: models.User = Depends(security.get_current_user)):
    return current_user

# 5. Protected Admin/Auditor Security Logs Stream
@app.get(
    "/api/v1/admin/audit-logs", 
    response_model=List[schemas.AuditLogResponse],
    tags=["Admin & Audit"]
)
def get_security_audit_logs(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(security.require_role(models.UserRole.AUDITOR))
):
    """
    Returns the real-time security event log stream.
    Accessible exclusively to users with 'auditor' or 'admin' roles.
    """
    logs = db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).limit(limit).all()
    return logs