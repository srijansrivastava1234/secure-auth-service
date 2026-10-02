from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Local SQLite database URL
SQLALCHEMY_DATABASE_URL = "sqlite:///./auth_service.db"

# Create SQLite engine
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False}
)

# Session factory for handling queries
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for all ORM models
Base = declarative_base()

def get_db():
    """Dependency that creates and closes a database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()