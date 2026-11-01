"""One admin account, with sessions held in memory."""
import base64
import hashlib
import hmac
import secrets
import threading
import time
from collections import deque

SESSION_S = 12 * 3600
MAX_FAILS = 5
MAX_TOTAL_FAILS = 30  # across all clients, because a client address can be faked
FAIL_WINDOW_S = 300
SCRYPT = dict(n=2 ** 14, r=8, p=1)


def hash_password(password):
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode(), salt=salt, **SCRYPT)
    return f"scrypt${base64.b64encode(salt).decode()}${base64.b64encode(key).decode()}"


def verify_password(password, stored):
    try:
        _, salt, key = stored.split("$")
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), **SCRYPT)
        return hmac.compare_digest(got, base64.b64decode(key))
    except ValueError:
        return False


def valid_hash(stored):
    parts = stored.split("$")
    if len(parts) != 3 or parts[0] != "scrypt":
        return False
    try:
        base64.b64decode(parts[1], validate=True)
        base64.b64decode(parts[2], validate=True)
    except ValueError:
        return False
    return True


class Auth:
    def __init__(self, user, password=None, password_hash=None):
        if not password and not password_hash:
            raise ValueError("Set PCAP_ANALYZER_ADMIN_PASSWORD or PCAP_ANALYZER_ADMIN_PASSWORD_HASH before starting")
        if password_hash and not valid_hash(password_hash):
            raise ValueError("PCAP_ANALYZER_ADMIN_PASSWORD_HASH is not a valid hash. Create one with: pcap-analyzer hash-password")
        self.user = user
        self.hash = password_hash or hash_password(password)
        self.sessions = {}
        self.fails = deque()  # (time, client). Blocking stops new entries, so this stays small.
        self.lock = threading.Lock()

    def blocked(self, client):
        cutoff = time.time() - FAIL_WINDOW_S
        with self.lock:
            while self.fails and self.fails[0][0] < cutoff:
                self.fails.popleft()
            return len(self.fails) >= MAX_TOTAL_FAILS or sum(c == client for _, c in self.fails) >= MAX_FAILS

    def login(self, client, user, password):
        ok_pw = verify_password(password, self.hash)  # always hash, so timing does not reveal the user name
        if hmac.compare_digest(user.encode(), self.user.encode()) and ok_pw:
            with self.lock:
                self.fails = deque(f for f in self.fails if f[1] != client)
            token = secrets.token_urlsafe(32)
            self.sessions[token] = time.time() + SESSION_S
            return token
        with self.lock:
            self.fails.append((time.time(), client))
        return None

    def valid(self, token):
        expiry = self.sessions.get(token or "")
        if expiry is None:
            return False
        if expiry < time.time():
            del self.sessions[token]
            return False
        return True

    def logout(self, token):
        self.sessions.pop(token or "", None)
