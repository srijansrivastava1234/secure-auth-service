from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import timedelta

import models
import schemas
import security
from database import engine, get_db

# Create database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Secure Identity & RBAC Microservice",
    version="1.0.0",
    description="Enterprise Authentication, Role-Based Access Control, and Audit Logging Service"
)

@app.get("/api/v1/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": "secure-identity-service",
        "version": "1.0.0",
        "database": "sqlite-connected"
    }

@app.post(
    "/api/v1/auth/register", 
    response_model=schemas.UserResponse, 
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"]
)
def register_user(user_in: schemas.UserCreate, db: Session = Depends(get_db)):
    """Registers a new user with bcrypt password hashing."""
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

@app.post(
    "/api/v1/auth/login", 
    response_model=schemas.Token,
    tags=["Authentication"]
)
def login_user(user_credentials: schemas.UserLogin, db: Session = Depends(get_db)):
    """
    Authenticates email and password, returning a signed JWT Bearer Token.
    """
    # 1. Fetch user by email
    user = db.query(models.User).filter(models.User.email == user_credentials.email).first()
    
    # 2. Verify password hash using bcrypt
    if not user or not security.verify_password(user_credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Create signed JWT access token (valid for 30 minutes)
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