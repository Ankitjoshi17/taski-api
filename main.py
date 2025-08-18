# main.py
import os
import time
import logging
from logging.handlers import RotatingFileHandler
import requests

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
from jose import jwt, jwk
from jose.exceptions import JWTError, JWKError
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from dotenv import load_dotenv

# -------------------------
# Env & Logging
# -------------------------
load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
API_AUDIENCE = os.getenv("API_AUDIENCE", CLIENT_ID)  # accept Client ID as fallback
AUTH_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"

log_file = "app.log"
log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
log_handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=3)
log_handler.setFormatter(log_formatter)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# -------------------------
# App & Middleware
# -------------------------
app = FastAPI(
    title="Secure API with OWASP Vulnerabilities (Testing Phase)",
    description="Deliberately misconfigured endpoints for testing Security Misconfiguration + other OWASP tests.",
    version="1.0.0",
)

# VULNERABLE: Overly-permissive CORS for testing (we will lock down later)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # ❌ any origin
    allow_credentials=True,
    allow_methods=["*"],          # ❌ any method
    allow_headers=["*"],          # ❌ any header
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# OAuth2 scheme (for Insomnia/Postman you’ll paste a Bearer token)
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=AUTH_URL,
    tokenUrl=TOKEN_URL,
    scopes={"access_as_user": "Access API as user"},
)

# -------------------------
# Simulated In-Memory Data
# -------------------------
users_db = {
    "user1": {
        "id": "user1",
        "username": "alice",
        "email": "alice@example.com",
        "role": "Admin",
        "password": "password123",  # weak on purpose for demo
    },
    "user2": {
        "id": "user2",
        "username": "bob",
        "email": "bob@example.com",
        "role": "User",
        "password": "password",
    },
}

# -------------------------
# JWKS Caching
# -------------------------
_jwks_cache = {"keys": None, "ts": 0}

def _get_jwks(force: bool = False):
    now = time.time()
    # refresh every 10 minutes or on demand
    if force or _jwks_cache["keys"] is None or (now - _jwks_cache["ts"]) > 600:
        resp = requests.get(JWKS_URL, timeout=10)
        resp.raise_for_status()
        _jwks_cache["keys"] = resp.json().get("keys", [])
        _jwks_cache["ts"] = now
        logger.info("JWKS fetched/refreshed.")
    return _jwks_cache["keys"]

# prime cache at startup
try:
    _get_jwks(force=True)
except Exception as e:
    logger.error(f"Failed to fetch JWKS at startup: {e}")

# -------------------------
# JWT Verification
# -------------------------
def verify_token(token: str):
    try:
        # Basic shape check
        if token.count(".") != 2:
            raise HTTPException(status_code=401, detail="Malformed token")

        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")
        alg = headers.get("alg", "RS256")  # Azure typically RS256

        if not kid:
            raise HTTPException(status_code=401, detail="Token missing kid")

        keys = _get_jwks()
        key_data = next((k for k in keys if k.get("kid") == kid), None)
        if not key_data:
            # refresh and retry once
            keys = _get_jwks(force=True)
            key_data = next((k for k in keys if k.get("kid") == kid), None)
            if not key_data:
                raise HTTPException(status_code=401, detail="Signing key not found")

        # Construct public key from JWK
        try:
            public_key = jwk.construct(key_data, algorithm=alg)
        except Exception:
            # fallback to RS256 if alg missing/unsupported on JWK
            public_key = jwk.construct(key_data, algorithm="RS256")

        # Let jose verify signature; we’ll validate audience manually
        payload = jwt.decode(
            token,
            public_key.to_pem().decode(),  # PEM string
            algorithms=[alg],
            issuer=ISSUER,
            options={"verify_aud": False},
        )

        # Manual audience validation (accept either api://GUID or plain GUID)
        aud = payload.get("aud")
        allowed = {API_AUDIENCE, CLIENT_ID, f"api://{CLIENT_ID}"}
        if isinstance(aud, list):
            if not any(a in allowed for a in aud):
                raise HTTPException(status_code=401, detail="Invalid audience")
        else:
            if aud not in allowed:
                raise HTTPException(status_code=401, detail="Invalid audience")

        return payload

    except HTTPException:
        raise
    except (JWTError, JWKError) as e:
        logger.error(f"JWT verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"Unexpected auth error: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")

# -------------------------
# Schemas
# -------------------------
class SecureDataRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    email: EmailStr
    comment: str | None = Field(None, max_length=500)

# For mass assignment demo (intentionally permissive in this testing phase)
class MassAssignmentModel(BaseModel):
    username: str
    email: EmailStr
    is_admin: bool | None = False
    role: str | None = "User"
    password: str | None = None

# -------------------------
# VULNERABLE Misconfiguration Endpoints (for testing)
# -------------------------
@app.get("/debug", summary="Vulnerable: debug/stacktrace")
@limiter.limit("10/minute")
def debug(request: Request, error: str | None = None):
    if error == "trace":
        # This will generate a 500 and (depending on server config) may leak details.
        raise RuntimeError("Simulated internal error for testing")
    return {"debug": "ok"}

@app.get("/config-dump", summary="Vulnerable: config exposure")
@limiter.limit("10/minute")
def config_dump(request: Request):
    return {
        "TENANT_ID": os.getenv("TENANT_ID"),
        "CLIENT_ID": os.getenv("CLIENT_ID"),
        "API_AUDIENCE": os.getenv("API_AUDIENCE"),
        "ENV": os.getenv("ENV", "dev"),
        "DEBUG": os.getenv("DEBUG", "false"),
    }

# -------------------------
# Core Routes
# -------------------------
@app.get("/", summary="Health check")
def root():
    return {"message": "API running"}

@app.get("/secure-data", summary="Admin-only secure data")
@limiter.limit("5/minute")
def secure_data(request: Request, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    roles = payload.get("roles") or []
    if "Admin" not in roles:
        raise HTTPException(status_code=403, detail="Admin role required")
    return {"message": "Secure data", "user": payload.get("preferred_username")}

@app.post("/submit-data", summary="Submit user data")
@limiter.limit("10/minute")
def submit_data(request: Request, data: SecureDataRequest, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    logger.info(f"{payload.get('preferred_username')} submitted: {data.dict()}")
    return {"message": "Data submitted", "data": data.dict()}

# BOLA demo (intentionally vulnerable)
@app.get("/users/{user_id}", summary="BOLA demo")
@limiter.limit("5/minute")
def get_user(request: Request, user_id: str, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    user = users_db.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # ❌ No ownership check here (vulnerable by design for the test phase)
    logger.warning(f"[BOLA] {payload.get('preferred_username')} accessed user {user_id}")
    return user

# Broken authentication (intentionally weak)
@app.post("/login", summary="Broken auth demo")
def login(data: dict):
    u = data.get("username")
    p = data.get("password")
    for user in users_db.values():
        if user["username"] == u and user["password"] == p:
            # In real life you'd issue a valid token; here we just simulate success
            return {"message": "Logged in", "fake_token": "insecure-demo-token"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

# Excessive Data Exposure (intentionally returns sensitive data)
@app.get("/public-profile", summary="Excessive Data Exposure demo")
def public_profile():
    return users_db  # ❌ returns passwords too (for testing)

# Mass Assignment (intentionally permissive)
@app.post("/mass-assign", summary="Mass Assignment demo")
def mass_assign(data: MassAssignmentModel):
    # Insecure: trust all incoming fields and "create" user
    created = data.dict()
    return {"created_user": created}

# Improper Asset Management (legacy endpoint)
@app.get("/v1/legacy-info", summary="Legacy endpoint demo")
def legacy_info():
    return {"version": "v1", "message": "Deprecated endpoint"}

# Extra: another exposure route
@app.get("/leak-data", summary="Excessive Data Exposure demo 2")
def leak_data():
    return {
        "id": "user2",
        "username": "bob",
        "email": "bob@example.com",
        "password": "pbkdf2_sha256$fake-hash",
        "role": "Admin",
        "auth_token": "xyz.jwt.token",
        "debug_info": {"request_ip": "192.168.1.5", "processing_time": "120ms"},
    }

# OpenAPI for ZAP imports
@app.get("/openapi.json", include_in_schema=False)
def openapi_json():
    return app.openapi()

# -------------------------
# Error Handlers
# -------------------------
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
