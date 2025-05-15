from pydantic import BaseModel, EmailStr
from typing import Optional


# ---------------------------
# User Schemas
# ---------------------------

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserLogin(UserBase):
    password: str

class UserOut(UserBase):
    id: int
    is_verified: bool

    class Config:
        orm_mode = True


# ---------------------------
# Token Schemas
# ---------------------------

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None


# ---------------------------
# Email Verification
# ---------------------------

class EmailVerification(BaseModel):
    token: str


# ---------------------------
# Forgot/Reset/Change Password
# ---------------------------

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str
