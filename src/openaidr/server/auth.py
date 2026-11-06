"""Local password authentication and browser request safeguards."""

import bcrypt

CONSOLE_COOKIE = "openaidr_session"
ADMIN_COOKIE = "openaidr_admin"
CSRF_HEADER = "X-OpenAIDR-CSRF"
MIN_PASSWORD_LENGTH = 10


def cookie_name(*, admin=False, secure=False):
    name = ADMIN_COOKIE if admin else CONSOLE_COOKIE
    return "__Host-" + name if secure else name


def hash_password(password: str) -> str:
    if len(password.encode()) < MIN_PASSWORD_LENGTH:
        raise ValueError("password too short")
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=10)).decode()


def check_password(password_hash: str, password: str) -> bool:
    if not isinstance(password_hash, str) or not isinstance(password, str):
        return False
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except (ValueError, TypeError):
        return False
