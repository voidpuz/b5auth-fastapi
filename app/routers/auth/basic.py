import base64
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session

from app.dependencies import db_dep
from app.models import User
from app.utils import verify_password

security = HTTPBasic()
security_dep = Annotated[HTTPBasicCredentials, Depends(security)]


def authenticate_user(credentials: HTTPBasicCredentials, db: Session) -> User:
    user = db.query(User).filter(User.username == credentials.username).first()
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user


# ============================================


def authenticate_user_by_hand(request: Request, db: Session) -> User:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Basic "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header",
            headers={"WWW-Authenticate": "Basic"},
        )

    try:
        username, password = decode_basic_auth(auth_header)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to decode credentials",
            headers={"WWW-Authenticate": "Basic"},
        ) from err

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user


def decode_basic_auth(auth_header: str) -> tuple[str, str]:
    encoded = auth_header.split(" ")[1]
    decoded_bytes = base64.b64decode(encoded)
    decoded_str = decoded_bytes.decode("utf-8")
    username, password = decoded_str.split(":", 1)
    return username, password


# =========================


def get_current_user_basic(db: db_dep, credentials: security_dep):
    return authenticate_user(credentials, db)


def get_current_user_basic_manual(db: db_dep, request: Request):
    return authenticate_user_by_hand(request, db)


basic_auth_dep = Annotated[User, Depends(get_current_user_basic)]
basic_auth_manual_dep = Annotated[User, Depends(get_current_user_basic_manual)]
