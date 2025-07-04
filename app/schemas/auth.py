from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class UserRegister(BaseModel):
    username: str
    password: str = Field(min_length=8, max_length=16)

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {"username": "username", "password": "password"}
        },
    }


class UserRegisterOut(BaseModel):
    id: int
    username: str
    email: EmailStr | None = None
    is_active: bool
    is_superuser: bool
    joined_at: datetime

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": 2,
                "username": "username",
                "email": "user@gmail.com",
                "is_active": True,
                "is_superuser": False,
                "joined_at": "2025-01-01 13:00:00.000",
            }
        },
    }


class UserSessionLogin(BaseModel):
    username: str
    password: str


class UserJWTLogin(BaseModel):
    username: str
    password: str


class JWTRefreshIn(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str