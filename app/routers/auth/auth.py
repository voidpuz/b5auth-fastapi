from fastapi import APIRouter, HTTPException

from app.dependencies import db_dep
from app.models import User
from app.routers.auth.basic import basic_auth_dep, basic_auth_manual_dep
from app.schemas import UserRegister, UserRegisterOut
from app.utils import hash_password

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRegisterOut)
async def register_user(session: db_dep, user_data: UserRegister):
    is_first_user = session.query(User).count() == 0

    is_user_exists = (
        session.query(User).filter(User.username == user_data.username).first()
    )
    if is_user_exists:
        raise HTTPException(
            status_code=400, detail="User with this email already exists."
        )

    db_user = User(
        username=user_data.username,
        hashed_password=hash_password(user_data.password),
        is_superuser=is_first_user,
    )

    session.add(db_user)
    session.commit()
    session.refresh(db_user)

    return db_user


@router.get("/basic/me", response_model=UserRegisterOut)
async def basic_me(session: db_dep, current_user: basic_auth_dep):
    return current_user

@router.get("/basic/manual/me", response_model=UserRegisterOut)
async def basic_manual_me(session: db_dep, current_user: basic_auth_manual_dep):
    return current_user