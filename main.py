from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import timedelta

import models
import schemas
import security
from database import engine, get_db

# Auto-create tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Secure Identity & RBAC Microservice",
    version="1.0.0",
    description="Enterprise Authentication, Role-Based Access Control, and Audit Logging Service"
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

# 3. Public Login (Generates JWT)
@app.post(
    "/api/v1/auth/login", 
    response_model=schemas.Token,
    tags=["Authentication"]
)
def login_user(user_credentials: schemas.UserLogin, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == user_credentials.email).first()
    if not user or not security.verify_password(user_credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

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

# 4. PROTECTED ENDPOINT (Requires Valid JWT)
@app.get(
    "/api/v1/users/me", 
    response_model=schemas.UserResponse,
    tags=["Users"]
)
def get_current_user_profile(current_user: models.User = Depends(security.get_current_user)):
    """Fetches the authenticated user's profile from the JWT token."""
    return current_user

# 5. RBAC PROTECTED ENDPOINT (Admin Only)
@app.get(
    "/api/v1/admin/analytics", 
    tags=["Admin"]
)
def get_admin_analytics(admin_user: models.User = Depends(security.require_role(models.UserRole.ADMIN))):
    """Restricted endpoint accessible exclusively to users with 'admin' role."""
    return {
        "message": "Welcome to the Admin Secure Command Center",
        "admin_email": admin_user.email,
        "system_metrics": {
            "auth_status": "nominal",
            "active_sessions": 1,
            "security_alerts": 0
        }
    }