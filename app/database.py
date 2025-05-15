from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# Use SQLite for simplicity
DATABASE_URL = "sqlite:///./jobportal.db"

# Create engine and session
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()

# Dependency to get DB session
def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
