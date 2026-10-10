import secrets
import hmac
import hashlib
from app.config import OTP_SECRET

def generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"

def hash_otp(identifier: str, code: str) -> str:
    # HMAC is used instead of a plain hash to prevent attackers from brute-forcing stolen hashes offline without the secret key.
    msg = f"{identifier}:{code}".encode("utf-8")
    key = OTP_SECRET.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

def verify_otp_hash(identifier: str, code: str, stored_hash: str) -> bool:
    computed_hash = hash_otp(identifier, code)
    return hmac.compare_digest(computed_hash, stored_hash)

def generate_session_token() -> str:
    return secrets.token_urlsafe(32)

def normalize_identifier(identifier: str) -> str:
    identifier = identifier.strip()
    if "@" in identifier:
        return identifier.lower()
    return identifier.replace(" ", "").replace("-", "")

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
