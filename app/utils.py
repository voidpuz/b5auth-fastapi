from app.models import User
from fastapi.security import HTTPBasicCredentials, HTTPBasic
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import Annotated

from passlib.context import CryptContext
import base64

security = HTTPBasic()
security_dep = Annotated[HTTPBasicCredentials, Depends(security)]

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


# Basic Auth functions

def authenticate_user_basic1(credentials: HTTPBasicCredentials, db: Session):
    user = db.query(User).filter(User.username == credentials.username).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    if not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Wrong password",
            headers={"WWW-Authenticate": "Basic"},
        )

    return user


# HTTP Basic on Hand

def authenticate_user_by_hand(request: Request, db: Session):
    auth_header = request.headers.get("Authorization")
    base64_credentials = auth_header.split(" ")[1]

    username, password = decode_base64_credentials(base64_credentials)

    user = db.query(User).filter(User.username == username).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    if not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Wrong password",
            headers={"WWW-Authenticate": "Basic"},
        )

    return user

def decode_base64_credentials(base64_string: str) -> tuple[str, str]:
    print("Incoming base64-token:", base64_string)
    decoded_str = base64.b64decode(base64_string).decode("utf-8")
    username, password = decoded_str.split(":")
    return username, password