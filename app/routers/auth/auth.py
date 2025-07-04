from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, Response, status
from jose import jwt, JWTError

from app.constants import (
    SESSION_COOKIE_NAME,
    SESSION_DURATION,
    REFRESH_TOKEN_EXPIRE_MINUTES,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    SECRET_KEY,
    ALGORITHM
)
from app.dependencies import current_user_jwt_dep, current_user_session_dep, db_dep
from app.models import AuthSession, User
from app.routers.auth.basic import basic_auth_dep, basic_auth_manual_dep
from app.schemas import (
    UserJWTLogin,
    UserRegister,
    UserRegisterOut,
    UserSessionLogin,
    JWTRefreshIn,
    TokenResponse,
)
from app.utils import hash_password, verify_password, create_jwt_token

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


# ========== Session Auth ==========


@router.post("/session/login")
async def login_session(db: db_dep, user_data: UserSessionLogin, response: Response):
    user = db.query(User).filter(User.username == user_data.username).first()
    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Create session
    session = AuthSession(
        user_id=user.id,
        expires_at=datetime.now(UTC) + SESSION_DURATION,
    )
    db.add(session)
    db.commit()

    # Set session ID in cookie
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session.id,
        httponly=True,
        max_age=int(SESSION_DURATION.total_seconds()),
        samesite="lax",
        secure=False,  # True if HTTPS
    )
    return {"message": "Logged in successfully"}


@router.post("/session/logout")
async def logout_session(
    db: db_dep,
    current_user: current_user_session_dep,
    request: Request,
    response: Response,
):
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        db.query(AuthSession).filter(AuthSession.id == session_id).delete()
        db.commit()

    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"message": "Logged out"}


# ========== JWT AUTH ==========


@router.post("/jwt/login")
async def login_jwt(db: db_dep, user_data: UserJWTLogin):
    user = db.query(User).filter(User.username == user_data.username).first()
    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_dict = {
        "username": user.username
    }

    access_token = create_jwt_token(user_dict, ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token = create_jwt_token(user_dict, REFRESH_TOKEN_EXPIRE_MINUTES)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
    }


@router.post("/jwt/me", response_model=UserRegisterOut)
async def jwt_me(current_user: current_user_jwt_dep):
    return current_user


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(token_data: JWTRefreshIn):
    try:
        payload = jwt.decode(token_data.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        # Check for validity of refresh token

        new_access_token = create_jwt_token(data={"username": username}, expires_delta=ACCESS_TOKEN_EXPIRE_MINUTES)
        return {"access_token": new_access_token, "refresh_token": token_data.refresh_token, "token_type": "bearer"}

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
