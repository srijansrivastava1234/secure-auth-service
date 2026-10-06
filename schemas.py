from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional, List
from models import UserRole

# Registration schema
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, description="Password must be at least 8 characters")
    role: UserRole = UserRole.USER

# Login schema
class UserLogin(BaseModel):
    email: EmailStr
    password: str

# Outgoing user profile schema
class UserResponse(BaseModel):
    id: int
    email: EmailStr
    role: UserRole
    created_at: datetime

    class Config:
        from_attributes = True

# Outgoing JWT Bearer Token schema
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int

# Outgoing Security Audit Log schema
class AuditLogResponse(BaseModel):
    id: int
    event_type: str
    email: str
    ip_address: Optional[str] = None
    timestamp: datetime

    class Config:
        from_attributes = True