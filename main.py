import os
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from database import engine, get_db
import models, schemas, auth

# Configure Rate Limiter (Redis if provided, else in-memory fallback)
redis_url = os.getenv("REDIS_URL", "memory://")
limiter = Limiter(key_func=get_remote_address, storage_uri=redis_url)

app = FastAPI(
    title="Secure Auth Service",
    description="Production-hardened RBAC and JWT Authentication Microservice",
    version="1.0.0"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.get("/healthz", tags=["System"])
def health_check():
    return {"status": "healthy", "service": "secure-auth-service"}


@app.post("/register", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED, tags=["Auth"])
def register(user_data: schemas.UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter(models.User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    hashed_password = auth.hash_password(user_data.password)
    user_role = user_data.role if user_data.role else models.UserRole.USER
    new_user = models.User(
        email=user_data.email,
        hashed_password=hashed_password,
        role=user_role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/login", response_model=schemas.Token, tags=["Auth"])
@limiter.limit("5/minute")
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    role_str = user.role.value if hasattr(user.role, "value") else str(user.role)
    access_token = auth.create_access_token(data={"sub": user.email, "role": role_str})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in_minutes": auth.ACCESS_TOKEN_EXPIRE_MINUTES
    }


@app.get("/users/me", response_model=schemas.UserResponse, tags=["Users"])
def get_current_user_profile(current_user: models.User = Depends(auth.get_current_user)):
    return current_user


@app.get("/admin/dashboard", tags=["Admin"])
def admin_only_route(current_user: models.User = Depends(auth.require_role("admin"))):
    return {"message": f"Welcome Admin {current_user.email}! Access granted to sensitive audit controls."}