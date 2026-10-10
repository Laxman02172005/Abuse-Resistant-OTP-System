OTP_TTL = 600
MAX_SENDS = 3
SEND_WINDOW = 600
MAX_ATTEMPTS = 5

# Value shape: {"code_hash": str, "created_at": float, "expires_at": float, "used": bool, "attempts": int}
otp_store = {}

# Value shape: list of floats [timestamp, timestamp, ...]
send_log = {}

# Value shape: {"identifier": str, "created_at": float}
sessions = {}
