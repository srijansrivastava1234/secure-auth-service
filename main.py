from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session

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
    """
    Registers a new user with bcrypt password hashing and duplicate email checks.
    """
    # 1. Check if user already exists
    existing_user = db.query(models.User).filter(models.User.email == user_in.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email address already exists."
        )

    # 2. Hash the plaintext password
    hashed_pwd = security.hash_password(user_in.password)

    # 3. Create and commit new user record
    new_user = models.User(
        email=user_in.email,
        hashed_password=hashed_pwd,
        role=user_in.role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user