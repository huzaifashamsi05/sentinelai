"""
Authentication: register, login, current-user info.

Implements the controls the handbook explicitly asks for on auth-adjacent
projects (Group D/E): bcrypt password hashing, role-based access
(Admin/Analyst), account lockout after repeated failed logins, and an
audit log of login events.
"""
from datetime import datetime, timedelta, timezone


def utcnow() -> datetime:
    """SQLite drops tzinfo on round-trip, so a timestamp read back from the
    DB is naive while datetime.now(timezone.utc) is aware — comparing them
    raises TypeError. Keep every stored/compared timestamp naive UTC."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.security import hash_password, verify_password, create_access_token
from app.db.database import get_db
from app.db.models import User, AuditLog
from app.schemas import UserCreate, UserOut, Token

router = APIRouter(prefix="/auth", tags=["auth"])

MAX_FAILED_ATTEMPTS = 3
LOCKOUT_MINUTES = 5


def _log(db: Session, username: str, action: str, detail: str = ""):
    db.add(AuditLog(username=username, action=action, detail=detail))
    db.commit()


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    user = User(
        username=payload.username,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    _log(db, user.username, "user_registered", f"role={user.role.value}")
    return user


@router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()

    if user and user.locked_until and user.locked_until > utcnow():
        remaining = int((user.locked_until - utcnow()).total_seconds())
        _log(db, form_data.username, "login_blocked_locked", f"{remaining}s remaining")
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Account locked. Try again in {remaining} seconds.",
        )

    if not user or not verify_password(form_data.password, user.hashed_password):
        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
                _log(db, form_data.username, "account_locked", f"after {user.failed_login_attempts} failed attempts")
            db.commit()
        _log(db, form_data.username, "login_failed")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")

    # success — reset lockout counters
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()
    _log(db, user.username, "login_success")

    token = create_access_token(subject=user.username, role=user.role.value)
    return Token(access_token=token, role=user.role)


@router.get("/me", response_model=UserOut)
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user
