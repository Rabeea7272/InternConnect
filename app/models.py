from sqlalchemy import Column, Integer, String, Boolean
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=True)  # Optional for Google users
    full_name = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    google_id = Column(String, nullable=True)        # For Google OAuth users
    resume_url = Column(String, nullable=True)
