import datetime

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status, Cookie
from sqlalchemy.orm import Session

from . import config, models
from .database import get_db

# Using the `bcrypt` library directly rather than passlib's CryptContext
# wrapper - passlib is unmaintained and its internal self-test breaks on
# bcrypt >= 4.x. bcrypt's own hashpw/checkpw API is stable and simpler.
_BCRYPT_MAX_BYTES = 72  # bcrypt silently ignores anything past this


def hash_password(password: str) -> str:
    truncated = password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    return bcrypt.hashpw(truncated, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    truncated = password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    return bcrypt.checkpw(truncated, password_hash.encode("utf-8"))


def create_access_token(user_id: int) -> str:
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=config.JWT_EXPIRE_MINUTES)
    payload = {"sub": str(user_id), "exp": expire}
    return jwt.encode(payload, config.SECRET_KEY, algorithm=config.JWT_ALGORITHM)


def decode_access_token(token: str) -> int:
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=[config.JWT_ALGORITHM])
        return int(payload["sub"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session")


def get_current_user(
    session_token: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> models.User:
    if not session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not logged in")
    user_id = decode_access_token(session_token)
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def get_current_user_optional(
    session_token: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> models.User | None:
    if not session_token:
        return None
    try:
        user_id = decode_access_token(session_token)
    except HTTPException:
        return None
    return db.query(models.User).filter(models.User.id == user_id).first()
