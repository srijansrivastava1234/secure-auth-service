import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, Enum, DateTime
from database import Base

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    AUDITOR = "auditor"
    USER = "user"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)