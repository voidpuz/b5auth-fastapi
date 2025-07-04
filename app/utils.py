from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request, status
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.constants import ALGORITHM, SECRET_KEY
from app.models import User

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


def create_jwt_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(UTC) + (
        timedelta(minutes=expires_delta) or timedelta(minutes=15)
    )
    print("Old to_encode:", to_encode)
    to_encode.update({"exp": expire})
    print("New to_encode:", to_encode)
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def parse_jwt_header(request: Request, db: Session) -> User:
    # Parsing the header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Authorization: Bearer <JWT_TOKEN>
    jwt_token = auth_header.split(" ")[1]
    try:
        decoded_jwt = jwt.decode(
            token=jwt_token,
            key=SECRET_KEY,
            algorithms=[ALGORITHM],
        )
    except JWTError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
        )
    print(decoded_jwt)

    username = decoded_jwt.get("username")
    password = decoded_jwt.get("password")

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or You are not authenticated.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
