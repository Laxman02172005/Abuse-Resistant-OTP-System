import os

# Parse .env manually since third-party packages like python-dotenv are forbidden.
def load_env():
    env_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    if os.path.exists(env_file):
        with open(env_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())

load_env()

OTP_SECRET = os.environ.get("OTP_SECRET")

if not OTP_SECRET:
    raise ValueError("OTP_SECRET environment variable is missing")
