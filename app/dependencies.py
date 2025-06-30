from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPBasicCredentials, HTTPBasic
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import User
from app.utils import (
    authenticate_user_basic1,
    authenticate_user_by_hand
)


security = HTTPBasic()
security_dep = Annotated[HTTPBasicCredentials, Depends(security)]


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dep = Annotated[Session, Depends(get_db)]


def get_current_user_basic1(credentials: security_dep, db: db_dep):
    return authenticate_user_basic1(credentials=credentials, db=db)

def get_current_user_basic2(request: Request, db: db_dep):
    return authenticate_user_by_hand(request=request, db=db)

current_user_basic_dep = Annotated[User, Depends(get_current_user_basic1)]
current_user_basic2_dep = Annotated[User, Depends(get_current_user_basic2)]