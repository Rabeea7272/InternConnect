import jwt
from datetime import datetime, timedelta
from typing import Optional
from pydantic import EmailStr
from passlib.context import CryptContext

# Secret key (keep it safe and secret)
SECRET_KEY = "SUPERSECRETKEY"  # Replace with your own secret key
ALGORITHM = "HS256"

# Token expiration time
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 minutes expiry

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Generate email verification token
def generate_token(email: EmailStr, expires_delta: Optional[timedelta] = None):
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {"sub": email, "exp": expire}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


# Verify email verification token
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        return email
    except jwt.ExpiredSignatureError:
        raise Exception("Token has expired")
    except jwt.JWTError:
        raise Exception("Invalid token")


# Hash password
def get_password_hash(password: str):
    return pwd_context.hash(password)


# Verify password
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)
