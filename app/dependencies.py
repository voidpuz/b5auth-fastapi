from typing import Annotated

from fastapi import Depends, Request, HTTPException

from app.models import User, AuthSession
from app.constants import SESSION_COOKIE_NAME, SESSION_DURATION
from sqlalchemy.orm import Session

from app.database import SessionLocal


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dep = Annotated[Session, Depends(get_db)]


def get_current_user_from_session(request: Request, db: Session = Depends(get_db)) -> User:
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        raise HTTPException(status_code=401, detail="No session cookie")

    session = db.query(AuthSession).filter(AuthSession.id == session_id).first()
    if not session or session.is_expired():
        raise HTTPException(status_code=401, detail="Session invalid or expired")

    return session.user

current_user_session_dep = Annotated[User, Depends(get_current_user_from_session)]