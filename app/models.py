import uuid
import pytz
from datetime import UTC, datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String, unique=True)
    email: Mapped[str] = mapped_column(String, nullable=True)
    hashed_password: Mapped[str] = mapped_column(String)
    joined_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(UTC))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)

    sessions: Mapped[list["AuthSession"]] = relationship(
        "AuthSession", back_populates="user"
    )

    def __repr__(self):
        return f"User(id={self.id!r}, username={self.username!r}, email={self.email!r})"


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(UTC))
    expires_at: Mapped[datetime] = mapped_column(DateTime)

    user = relationship("User", back_populates="sessions")

    def is_expired(self):
        timezone = self.expires_at.tzinfo
        now_in_tz = datetime.now(timezone)
        return now_in_tz > self.expires_at
