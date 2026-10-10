import time
import threading
import re
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from app.crypto_utils import normalize_identifier, generate_otp, hash_otp, verify_otp_hash, generate_session_token, hash_token
from app.store import otp_store, send_log, OTP_TTL, MAX_SENDS, SEND_WINDOW, sessions, MAX_ATTEMPTS

app = FastAPI()

class IdentifierRequest(BaseModel):
    identifier: str

class VerifyRequest(BaseModel):
    identifier: str
    code: str

lock = threading.Lock()

def deliver_otp(identifier: str, code: str):
    print(f"DELIVER_OTP: Sending {code} to {identifier}")

def prune_send_log(identifier: str, current_time: float):
    if identifier in send_log:
        send_log[identifier] = [ts for ts in send_log[identifier] if current_time - ts <= SEND_WINDOW]

@app.post("/auth/send")
def send_otp(request: IdentifierRequest):
    identifier = normalize_identifier(request.identifier)
    
    if not identifier:
        return JSONResponse(status_code=400, content={"message": "Invalid identifier"})
        
    is_email = bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", identifier))
    is_phone = bool(re.fullmatch(r"\+?\d{7,15}", identifier))
    
    if not (is_email or is_phone):
        return JSONResponse(status_code=400, content={"message": "Invalid identifier"})

    with lock:
        current_time = time.time()
        prune_send_log(identifier, current_time)
        
        current_logs = send_log.get(identifier, [])
        if len(current_logs) >= MAX_SENDS:
            return JSONResponse(status_code=429, content={"message": "Too many requests, try again later"})
            
        code = generate_otp()
        code_hash = hash_otp(identifier, code)
        
        otp_store[identifier] = {
            "code_hash": code_hash,
            "created_at": current_time,
            "expires_at": current_time + OTP_TTL,
            "used": False,
            "attempts": 0
        }
        
        if identifier not in send_log:
            send_log[identifier] = []
        send_log[identifier].append(current_time)
        
    deliver_otp(identifier, code)
    
    return {"message": f"OTP sent to {identifier}"}

@app.post("/auth/verify")
def verify_otp(request: VerifyRequest):
    with lock:
        now = time.time()
        identifier = normalize_identifier(request.identifier)
        
        if identifier not in otp_store:
            return JSONResponse(status_code=400, content={"message": "Invalid or expired code"})
            
        record = otp_store[identifier]
        
        if record["used"]:
            return JSONResponse(status_code=400, content={"message": "Invalid or expired code"})
            
        if now >= record["expires_at"]:
            return JSONResponse(status_code=400, content={"message": "Invalid or expired code"})
            
        if record["attempts"] >= MAX_ATTEMPTS:
            return JSONResponse(status_code=429, content={"message": "Too many failed attempts. Request a new code."})
            
        if not verify_otp_hash(identifier, request.code, record["code_hash"]):
            record["attempts"] += 1
            if record["attempts"] >= MAX_ATTEMPTS:
                return JSONResponse(status_code=429, content={"message": "Too many failed attempts. Request a new code."})
            else:
                return JSONResponse(status_code=400, content={
                    "message": "Invalid or expired code",
                    "attempts_remaining": MAX_ATTEMPTS - record["attempts"]
                })
                
        record["used"] = True
        
        token = generate_session_token()
        token_hash = hash_token(token)
        sessions[token_hash] = {
            "identifier": identifier,
            "created_at": now
        }
        
        return {"message": "Verified", "session_token": token}
