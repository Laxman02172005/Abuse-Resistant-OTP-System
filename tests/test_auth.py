import os
import pytest
os.environ["OTP_SECRET"] = "0" * 64

from fastapi.testclient import TestClient
from app.main import app
from app.store import otp_store, send_log, sessions
from app.crypto_utils import hash_token, hash_otp

client = TestClient(app)

class MockTime:
    def __init__(self):
        self.current = 10000.0
    def time(self):
        return self.current
    def advance(self, seconds):
        self.current += seconds

mock_time = MockTime()

@pytest.fixture(autouse=True)
def reset_state(monkeypatch):
    otp_store.clear()
    send_log.clear()
    sessions.clear()
    monkeypatch.setattr("app.main.generate_otp", lambda: "123456")
    monkeypatch.setattr("app.main.time.time", mock_time.time)
    mock_time.current = 10000.0

def test_send_success():
    resp = client.post("/auth/send", json={"identifier": "a@x.com"})
    assert resp.status_code == 200
    assert "123456" not in resp.text

def test_send_rate_limit():
    for _ in range(3):
        assert client.post("/auth/send", json={"identifier": "a@x.com"}).status_code == 200
    resp = client.post("/auth/send", json={"identifier": "a@x.com"})
    assert resp.status_code == 429

def test_send_limit_per_identifier():
    for _ in range(3):
        client.post("/auth/send", json={"identifier": "a@x.com"})
    assert client.post("/auth/send", json={"identifier": "b@x.com"}).status_code == 200

def test_send_limit_case_insensitive():
    for _ in range(3):
        client.post("/auth/send", json={"identifier": "a@x.com"})
    assert client.post("/auth/send", json={"identifier": "A@X.com"}).status_code == 429

def test_resending_does_not_reset_limit():
    assert client.post("/auth/send", json={"identifier": "a@x.com"}).status_code == 200
    mock_time.advance(300)
    assert client.post("/auth/send", json={"identifier": "a@x.com"}).status_code == 200
    mock_time.advance(200)
    assert client.post("/auth/send", json={"identifier": "a@x.com"}).status_code == 200
    mock_time.advance(50)
    assert client.post("/auth/send", json={"identifier": "a@x.com"}).status_code == 429

def test_send_limit_resets_after_window():
    for _ in range(3):
        client.post("/auth/send", json={"identifier": "a@x.com"})
    mock_time.advance(601)
    assert client.post("/auth/send", json={"identifier": "a@x.com"}).status_code == 200

def test_invalid_identifier():
    resp = client.post("/auth/send", json={"identifier": "invalid"})
    assert resp.status_code == 400

def test_otp_store_holds_hash_not_code():
    client.post("/auth/send", json={"identifier": "a@x.com"})
    record = otp_store["a@x.com"]
    assert "123456" not in str(otp_store)
    assert record["code_hash"] == hash_otp("a@x.com", "123456")

def test_verify_wrong_codes_lockout():
    client.post("/auth/send", json={"identifier": "a@x.com"})
    for i in range(4):
        resp = client.post("/auth/verify", json={"identifier": "a@x.com", "code": "wrong"})
        assert resp.status_code == 400
        assert resp.json()["attempts_remaining"] == 4 - i
    
    resp = client.post("/auth/verify", json={"identifier": "a@x.com", "code": "wrong"})
    assert resp.status_code == 429

def test_verify_correct_code_after_lockout():
    client.post("/auth/send", json={"identifier": "a@x.com"})
    for _ in range(5):
        client.post("/auth/verify", json={"identifier": "a@x.com", "code": "wrong"})
    
    resp = client.post("/auth/verify", json={"identifier": "a@x.com", "code": "123456"})
    assert resp.status_code == 429

def test_verify_correct_code_single_use():
    client.post("/auth/send", json={"identifier": "a@x.com"})
    resp = client.post("/auth/verify", json={"identifier": "a@x.com", "code": "123456"})
    assert resp.status_code == 200
    assert "session_token" in resp.json()
    
    resp2 = client.post("/auth/verify", json={"identifier": "a@x.com", "code": "123456"})
    assert resp2.status_code == 400

def test_verify_expiry():
    client.post("/auth/send", json={"identifier": "a@x.com"})
    mock_time.advance(600)
    resp = client.post("/auth/verify", json={"identifier": "a@x.com", "code": "123456"})
    assert resp.status_code == 400
    
    client.post("/auth/send", json={"identifier": "b@x.com"})
    mock_time.advance(599)
    resp2 = client.post("/auth/verify", json={"identifier": "b@x.com", "code": "123456"})
    assert resp2.status_code == 200

def test_sessions_stores_hash():
    client.post("/auth/send", json={"identifier": "a@x.com"})
    resp = client.post("/auth/verify", json={"identifier": "a@x.com", "code": "123456"})
    token = resp.json()["session_token"]
    
    assert token not in sessions
    assert hash_token(token) in sessions

def test_verify_unknown_identifier():
    client.post("/auth/send", json={"identifier": "a@x.com"})
    resp_wrong = client.post("/auth/verify", json={"identifier": "a@x.com", "code": "wrong"})
    expected_msg = resp_wrong.json()["message"]
    
    resp = client.post("/auth/verify", json={"identifier": "unknown@x.com", "code": "123456"})
    assert resp.status_code == 400
    assert resp.json()["message"] == expected_msg
