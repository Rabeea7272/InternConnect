from fastapi import FastAPI, Request, Form, Depends
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse, HTMLResponse
from sqlalchemy.orm import Session
from app import models, database, security
from app.database import engine, get_db
from app.email import send_verification_email
from itsdangerous import URLSafeTimedSerializer
from fastapi.staticfiles import StaticFiles
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI()

# Session middleware
app.add_middleware(
    SessionMiddleware,
    secret_key="SUPERSECRETKEY",  # Use a strong secret key in production
    same_site="lax",              # Make cookies accessible across same-site redirects
    https_only=False,             # Allow over HTTP (for local dev)
    session_cookie="session"      # Set a fixed cookie name
)

# OAuth setup for Google
oauth = OAuth()
oauth.register(
    name='google',
    client_id="34449916169-l6kof2805a8k55sdrq776kr2e1uatfv2.apps.googleusercontent.com",
    client_secret="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",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile"
    }
)


templates = Jinja2Templates(directory="app/templates")
# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

models.Base.metadata.create_all(bind=engine)

# Use a strong secret key in production
serializer = URLSafeTimedSerializer("SUPERSECRETKEY")

@app.get("/")
def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/register")
def register_get(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
def register_post(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    try:
        existing_user = db.query(models.User).filter(models.User.email == email).first()
        if existing_user:
            return templates.TemplateResponse("register.html", {"request": request, "msg": "Email already registered"})

        hashed_password = security.get_password_hash(password)
        new_user = models.User(email=email, hashed_password=hashed_password, is_verified=False)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Generate verification link
        token = serializer.dumps(email, salt="email-confirm")
        verification_link = f"http://127.0.0.1:8000/verify-email?token={token}"
        send_verification_email(email, verification_link)

        return templates.TemplateResponse("message.html", {"request": request, "msg": "Please check your email to verify your account."})

    except Exception as e:
        # Log the exception for better debugging
        print(f"Error during registration: {e}")
        return templates.TemplateResponse("register.html", {"request": request, "msg": "Something went wrong. Please try again."})

@app.get("/login")
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login_post(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    try:
        user = db.query(models.User).filter(models.User.email == email).first()
        if not user:
            return templates.TemplateResponse("login.html", {"request": request, "msg": "Invalid credentials"})

        if not user.is_verified:
            return templates.TemplateResponse("login.html", {"request": request, "msg": "Email not verified. Check your inbox."})

        if not security.verify_password(password, user.hashed_password):
            return templates.TemplateResponse("login.html", {"request": request, "msg": "Incorrect password"})

        # If login is successful
        return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})

    except Exception as e:
        print(f"Error during login: {e}")
        return templates.TemplateResponse("login.html", {"request": request, "msg": "Something went wrong. Please try again."})

@app.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        email = serializer.loads(token, salt="email-confirm", max_age=3600)  # Token expiration set to 1 hour
        user = db.query(models.User).filter(models.User.email == email).first()
        if user:
            user.is_verified = True
            db.commit()
            return RedirectResponse(url="/login", status_code=302)
        return {"msg": "Invalid or expired token."}
    except Exception as e:
        return {"msg": f"Verification failed: {str(e)}"}

# Forgot Password Request - Step 1
@app.get("/forgot-password")
def forgot_password(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})

@app.post("/forgot-password")
def forgot_password_post(request: Request, email: str = Form(...), db: Session = Depends(get_db)):
    try:
        user = db.query(models.User).filter(models.User.email == email).first()
        if not user:
            return templates.TemplateResponse("forgot_password.html", {"request": request, "msg": "Email not found"})

        # Generate reset password link
        token = serializer.dumps(email, salt="password-reset")
        reset_link = f"http://127.0.0.1:8000/reset-password?token={token}"
        send_verification_email(email, reset_link)

        return templates.TemplateResponse("message.html", {"request": request, "msg": "Check your email to reset your password."})
    except Exception as e:
        return templates.TemplateResponse("forgot_password.html", {"request": request, "msg": f"Error: {str(e)}"})

# Reset Password - Step 2
@app.get("/reset-password")
def reset_password(request: Request, token: str):
    return templates.TemplateResponse("reset_password.html", {"request": request, "token": token})

@app.post("/reset-password")
def reset_password_post(request: Request, token: str = Form(...), new_password: str = Form(...), db: Session = Depends(get_db)):
    try:
        email = serializer.loads(token, salt="password-reset", max_age=3600)  # Token expiration set to 1 hour
        user = db.query(models.User).filter(models.User.email == email).first()

        if not user:
            return templates.TemplateResponse("reset_password.html", {"request": request, "msg": "Invalid token or user not found."})

        # Update password
        hashed_password = security.get_password_hash(new_password)
        user.hashed_password = hashed_password
        db.commit()

        return RedirectResponse(url="/login", status_code=302)
    except Exception as e:
        return templates.TemplateResponse("reset_password.html", {"request": request, "msg": f"Error: {str(e)}"})

@app.get("/auth/google")
async def auth_google(request: Request):
    redirect_uri = "http://127.0.0.1:8000/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google/callback")
async def auth_google_callback(request: Request, db: Session = Depends(get_db)):
    try:
        token = await oauth.google.authorize_access_token(request)

        # Try to get user info via ID token first
        user_info = token.get("userinfo")
        if not user_info:
            user_info = await oauth.google.parse_id_token(request, token)

        if not user_info:
            # Fallback: fetch from userinfo endpoint
            resp = await oauth.google.get("userinfo", token=token)
            user_info = resp.json()

        email = user_info.get("email")
        name = user_info.get("name")

        if not email:
            raise Exception("Email not returned by Google")

        user = db.query(models.User).filter(models.User.email == email).first()

        if not user:
            user = models.User(email=email, hashed_password="", is_verified=True)
            db.add(user)
            db.commit()
            db.refresh(user)

        return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})

    except Exception as e:
        print("Google login error:", str(e))
        return templates.TemplateResponse("login.html", {
            "request": request,
            "msg": f"Google login failed: {str(e)}"
        })