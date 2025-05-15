from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from pydantic import EmailStr
import asyncio

# Configure your email settings
conf = ConnectionConfig(
    MAIL_USERNAME="ahmadrehan1024@gmail.com",
    MAIL_PASSWORD="waum ovzt ijua ucss",  # Replace with your Gmail app password
    MAIL_FROM="ahmadrehan1024@gmail.com",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
)

def send_verification_email(email: EmailStr, link: str):
    message = MessageSchema(
        subject="Verify your email",
        recipients=[email],
        body=f"Hi,\n\nPlease verify your email by clicking the link below:\n{link}\n\nThank you!",
        subtype="plain"
    )
    fm = FastMail(conf)
    try:
        asyncio.run(fm.send_message(message))
        print(f"Verification email sent to {email}")
    except Exception as e:
        print(f"Error sending verification email: {str(e)}")


