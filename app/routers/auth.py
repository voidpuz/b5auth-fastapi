from fastapi import APIRouter, HTTPException, Depends

from typing import Annotated

from app.dependencies import db_dep, current_user_basic_dep, current_user_basic2_dep
from app.models import User
from app.schemas import UserRegister, UserRegisterOut
from app.utils import hash_password

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRegisterOut)
async def register_user(session: db_dep, user_data: UserRegister):
    is_first_user = session.query(User).count() == 0

    is_user_exists = session.query(User).filter(User.username == user_data.username).first()
    if is_user_exists:
        raise HTTPException(
            status_code=400,
            detail="User with this email already exists."
        )
    
    db_user = User(
        username = user_data.username,
        hashed_password = hash_password(user_data.password),
        is_superuser = is_first_user
    )

    session.add(db_user)
    session.commit()
    session.refresh(db_user)

    return db_user


@router.get("/users/{id}", response_model=UserRegisterOut)
async def get_user_with_id(session: db_dep, id: int):
    user = session.query(User).filter(User.id == id).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return user



# ======== BASIC AUTH ========

@router.get("/basic/me", response_model=UserRegisterOut)
async def get_me_basic(db: db_dep, current_user: current_user_basic_dep):
    return current_user

@router.get("/basic2/me", response_model=UserRegisterOut)
async def get_me_basic2(db: db_dep, current_user: current_user_basic2_dep):
    return current_user