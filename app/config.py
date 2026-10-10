import os

OTP_SECRET = os.environ.get("OTP_SECRET")

if not OTP_SECRET:
    raise ValueError("OTP_SECRET environment variable is missing")
