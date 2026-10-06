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

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String, nullable=False, index=True)  # LOGIN_SUCCESS, LOGIN_FAILED, ACCESS_DENIED
    email = Column(String, nullable=False, index=True)
    ip_address = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)