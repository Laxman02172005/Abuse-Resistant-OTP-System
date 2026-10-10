import time
import hashlib
import hmac
import os
import sys

# Add parent directory to path to import app config
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.config import OTP_SECRET

def run_sha256_benchmark():
    identifier = "test@example.com"
    start = time.time()
    for i in range(1_000_000):
        code = f"{i:06d}"
        msg = f"{identifier}:{code}".encode("utf-8")
        hashlib.sha256(msg).hexdigest()
    return time.time() - start

def run_hmac_benchmark():
    identifier = "test@example.com"
    key = OTP_SECRET.encode("utf-8")
    start = time.time()
    for i in range(1_000_000):
        code = f"{i:06d}"
        msg = f"{identifier}:{code}".encode("utf-8")
        hmac.new(key, msg, hashlib.sha256).hexdigest()
    return time.time() - start

if __name__ == "__main__":
    print("Benchmarking 1,000,000 OTP hashes...")
    
    sha256_time = run_sha256_benchmark()
    print(f"Plain SHA-256 time: {sha256_time:.2f} seconds")
    
    hmac_time = run_hmac_benchmark()
    print(f"HMAC-SHA256 time: {hmac_time:.2f} seconds")
