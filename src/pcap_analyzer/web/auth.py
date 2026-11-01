"""One admin account, with sessions held in memory."""
import base64
import hashlib
import hmac
import secrets
import time

SESSION_S = 12 * 3600
MAX_FAILS = 5
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
        self.fails = {}

    def blocked(self, client):
        now = time.time()
        self.fails[client] = [t for t in self.fails.get(client, []) if now - t < FAIL_WINDOW_S]
        return len(self.fails[client]) >= MAX_FAILS

    def login(self, client, user, password):
        ok_pw = verify_password(password, self.hash)  # always hash, so timing does not reveal the user name
        if hmac.compare_digest(user.encode(), self.user.encode()) and ok_pw:
            self.fails.pop(client, None)
            token = secrets.token_urlsafe(32)
            self.sessions[token] = time.time() + SESSION_S
            return token
        self.fails.setdefault(client, []).append(time.time())
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
