from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from models import UserRole

# Schema for incoming registration payload
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, description="Password must be at least 8 characters")
    role: UserRole = UserRole.USER

# Schema for outgoing user data (NEVER returns hashed_password!)
class UserResponse(BaseModel):
    id: int
    email: EmailStr
    role: UserRole
    created_at: datetime

    class Config:
        from_attributes = True