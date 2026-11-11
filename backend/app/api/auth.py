"""
Authentication: register, login, current-user info.

Implements the controls the handbook explicitly asks for on auth-adjacent
projects (Group D/E): bcrypt password hashing, role-based access
(Admin/Analyst), per-(username, IP) login throttling (core/login_throttle.py),
and an audit log of login events.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core import login_throttle
from app.core.security import hash_password, verify_password, create_access_token
from app.db.database import get_db
from app.db.models import User, UserRole, AuditLog
from app.schemas import UserCreate, UserOut, Token

router = APIRouter(prefix="/auth", tags=["auth"])

# A fixed, constant-looking hash that doesn't correspond to anyone's real
# password. Used so login() always runs a bcrypt check even when the
# username doesn't exist — see the F-04 comment on login() below for why.
_DUMMY_HASH = hash_password("this-is-not-a-real-password-used-only-for-constant-time-login")


def _log(db: Session, username: str, action: str, detail: str = ""):
    db.add(AuditLog(username=username, action=action, detail=detail))
    db.commit()


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    # Self-registration is always Analyst — never trust a client-supplied
    # role. Admin exists only via the startup seed (main.py's
    # seed_default_users); promoting someone to Admin is an out-of-band,
    # database-level action, not something the public /register form can do.
    user = User(
        username=payload.username,
        hashed_password=hash_password(payload.password),
        role=UserRole.analyst,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    _log(db, user.username, "user_registered", f"role={user.role.value}")
    return user


@router.post("/login", response_model=Token)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"

    # F-03: throttle is per (username, ip), not per username alone — see
    # core/login_throttle.py's docstring for why the old account-wide lock
    # was a denial-of-service against the admin account.
    remaining = login_throttle.seconds_locked(form_data.username, client_ip)
    if remaining > 0:
        _log(db, form_data.username, "login_blocked_throttled", f"{remaining}s remaining, ip={client_ip}")
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Too many failed attempts from this IP. Try again in {remaining} seconds.",
        )

    user = db.query(User).filter(User.username == form_data.username).first()

    # F-04: ALWAYS run a bcrypt check — against the real hash if the user
    # exists, against a fixed dummy hash if not — instead of short-circuiting
    # on "user is None". Skipping bcrypt entirely for unknown usernames made
    # an existing-user login ~45x slower than an unknown-user one (317ms vs
    # 7ms), which is enough of a timing gap to enumerate valid usernames.
    password_ok = verify_password(form_data.password, user.hashed_password if user else _DUMMY_HASH)

    if not user or not password_ok:
        login_throttle.record_failure(form_data.username, client_ip)
        _log(db, form_data.username, "login_failed", f"ip={client_ip}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")

    login_throttle.record_success(form_data.username, client_ip)
    _log(db, user.username, "login_success")

    token = create_access_token(subject=user.username, role=user.role.value)
    return Token(access_token=token, role=user.role)


@router.get("/me", response_model=UserOut)
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user
