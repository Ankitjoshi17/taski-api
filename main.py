# main.py — Final Patched Version
import os
import logging
from logging.handlers import RotatingFileHandler
from typing import Dict, Any, Optional, List

import requests
from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2AuthorizationCodeBearer
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from jose import jwt, jwk
from jose.exceptions import JWTError, JWKError
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from dotenv import load_dotenv

# =========================
# Environment
# =========================
load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
# Support one or many audiences (comma-separated), accepting either GUID or api://GUID
API_AUDIENCE = os.getenv("API_AUDIENCE", CLIENT_ID) or ""
ALLOWED_AUDIENCES: List[str] = [a.strip() for a in API_AUDIENCE.split(",") if a.strip()]
if not ALLOWED_AUDIENCES:
    raise RuntimeError("API_AUDIENCE must be set (e.g. 'cc4f...e3c' or 'api://cc4f...e3c').")

if not TENANT_ID or not CLIENT_ID:
    raise RuntimeError("TENANT_ID and CLIENT_ID must be set for Azure mode.")

AUTH_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"

# =========================
# Logging
# =========================
log_file = "app.log"
log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
log_handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=3)
log_handler.setFormatter(log_formatter)
logger = logging.getLogger("api")
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# =========================
# FastAPI + Rate Limiting
# =========================
app = FastAPI(
    title="Secure API (Azure Mode)",
    description="FastAPI API protected by Microsoft Entra ID (OAuth2/JWT), with OWASP-aligned mitigations.",
    version="2.0.0",
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# =========================
# Security Headers Middleware
# =========================
SECURITY_HEADERS = os.getenv("SECURITY_HEADERS", "true").lower() == "true"

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    if SECURITY_HEADERS:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        # CSP typically for HTML; omit for pure JSON APIs unless serving pages
        # response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none';")
    return response

# =========================
# OAuth2 Scheme
# =========================
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=AUTH_URL,
    tokenUrl=TOKEN_URL,
    scopes={"access_as_user": "Access API as user"},
)

# =========================
# JWKS Cache + Token Verification
# =========================
JWKS_CACHE: Dict[str, Any] = {"keys": []}

def fetch_jwks() -> Dict[str, Any]:
    resp = requests.get(JWKS_URL, timeout=10)
    resp.raise_for_status()
    return resp.json()

def get_public_key_for_kid(kid: str) -> jwk.Key:
    # Try cached first
    key_data = next((k for k in JWKS_CACHE.get("keys", []) if k.get("kid") == kid), None)
    if key_data:
        return jwk.construct(key_data)

    # Refresh cache and try again
    try:
        JWKS_CACHE.update(fetch_jwks())
    except Exception as e:
        logger.error(f"Failed to refresh JWKS: {e}")
        raise HTTPException(status_code=401, detail="Unable to refresh JWKS")

    key_data = next((k for k in JWKS_CACHE.get("keys", []) if k.get("kid") == kid), None)
    if not key_data:
        raise HTTPException(status_code=401, detail="Signing key not found for token")
    return jwk.construct(key_data)

def verify_audience(aud: Any) -> bool:
    # Azure may put a single string in "aud"; sometimes clients look at "azp".
    if isinstance(aud, str):
        return aud in ALLOWED_AUDIENCES
    if isinstance(aud, list):
        return any(a in ALLOWED_AUDIENCES for a in aud)
    return False

def verify_token(token: str) -> Dict[str, Any]:
    try:
        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Token missing 'kid'")

        public_key = get_public_key_for_kid(kid)

        # Decode & validate standard claims
        payload = jwt.decode(
            token,
            public_key.to_pem().decode(),
            algorithms=["RS256"],  # Azure v2.0 issues RS256 today
            audience=ALLOWED_AUDIENCES,  # accepts list
            issuer=ISSUER,
            options={"require_aud": True, "require_iat": True, "require_exp": True},
        )

        # Extra guard for odd cases where library didn't match audience list
        if not verify_audience(payload.get("aud")):
            raise HTTPException(status_code=401, detail="Invalid audience")

        return payload

    except (JWTError, JWKError) as e:
        logger.error(f"JWT verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected auth error: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    return verify_token(token)

# =========================
# Data Models (Pydantic)
# =========================
class SecureDataRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    email: EmailStr
    comment: Optional[str] = Field(None, max_length=500)

class CreateUserInput(BaseModel):
    # Patched mass-assignment: forbid extra fields; only allow safe fields
    model_config = ConfigDict(extra="forbid")
    username: str
    email: EmailStr

# Auth model for demo /login (kept for evaluation, now patched)
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(..., min_length=1, max_length=128)

# =========================
# In-memory Data (demo only)
# =========================
# NOTE: In production use a database/service, not in-memory globals.
USERS_DB: Dict[str, Dict[str, Any]] = {
    "user1": {"id": "user1", "username": "alice", "email": "alice@example.com", "role": "Admin"},
    "user2": {"id": "user2", "username": "bob", "email": "bob@example.com", "role": "User"},
}
# Map preferred_username/email to user_id for ownership checks
EMAIL_TO_ID = {"alice@example.com": "user1", "bob@example.com": "user2"}

# =========================
# Routes
# =========================
@app.get("/", summary="Health")
def health():
    return {"message": "API running (Azure mode)"}

@app.get("/_whoami", summary="Return claims (debug)")
def whoami(user=Depends(get_current_user)):
    # Careful: do not log/return sensitive claims in prod; this is for testing
    return {
        "preferred_username": user.get("preferred_username"),
        "oid": user.get("oid"),
        "roles": user.get("roles", []),
        "aud": user.get("aud"),
        "iss": user.get("iss"),
        "tid": user.get("tid"),
        "scp": user.get("scp"),
        "azp": user.get("azp"),
    }

@app.post("/login", summary="Demo login (patched: rate limiting & logging; no weak auth accepted)")
@limiter.limit("5/minute")
def login(request: Request, body: LoginRequest):
    """
    Patched behaviour for study endpoint:
    - Rate limiting & logging enforced.
    - Weak passwords (e.g., '123456') are NOT accepted.
    - No tokens are issued here; primary auth is Azure Entra ID OAuth2/JWT.
    Future work: integrate bcrypt/argon2 for local credential flows if required.
    """
    username = body.username.strip().lower()
    logger.info(f"LOGIN ATTEMPT user={username} ip={request.client.host}")
    # Always reject (this demo endpoint is retained only for evaluation with controls applied)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

@app.get("/secure-data", summary="Admin-only secure data")
@limiter.limit("5/minute")
def secure_data(request: Request, user=Depends(get_current_user)):
    roles = user.get("roles") or []
    if "Admin" not in roles:
        raise HTTPException(status_code=403, detail="Admin role required")
    logger.info(f"{user.get('preferred_username')} accessed /secure-data")
    return {"message": "Secure data", "user": user.get("preferred_username")}

@app.post("/submit-data", summary="Submit user data (validated)")
@limiter.limit("10/minute")
def submit_data(request: Request, payload: SecureDataRequest, user=Depends(get_current_user)):
    logger.info(f"{user.get('preferred_username')} submitted data {payload.model_dump()}")
    return {"message": "Data received", "submitted": payload.model_dump()}

@app.get("/users/{user_id}", summary="Get user (BOLA patched: ownership/RBAC enforced)")
@limiter.limit("10/minute")
def get_user_by_id(request: Request, user_id: str, user=Depends(get_current_user)):
    record = USERS_DB.get(user_id)
    if not record:
        raise HTTPException(status_code=404, detail="User not found")

    # Ownership (user can access their own record) or Admin role can access any
    caller_email = user.get("preferred_username")
    caller_id = EMAIL_TO_ID.get(caller_email, user.get("oid") or user.get("sub"))
    roles = user.get("roles") or []

    if caller_id != user_id and "Admin" not in roles:
        raise HTTPException(status_code=403, detail="Forbidden (ownership check)")

    return {
        "id": record["id"],
        "username": record["username"],
        "email": record["email"],
        "role": record["role"],
    }

@app.post("/users", summary="Create user (mass-assignment patched)")
@limiter.limit("10/minute")
def create_user(request: Request, body: CreateUserInput, user=Depends(get_current_user)):
    # Server-controlled defaults only
    new_id = body.username.lower()
    if new_id in USERS_DB:
        raise HTTPException(status_code=409, detail="User already exists")
    USERS_DB[new_id] = {
        "id": new_id,
        "username": body.username,
        "email": body.email,
        "role": "User",  # enforced by server, not client
    }
    logger.info(f"{user.get('preferred_username')} created user {new_id}")
    return {"created": USERS_DB[new_id]}

# OpenAPI export (useful for ZAP import)
@app.get("/openapi.json", include_in_schema=False)
def openapi_spec():
    return app.openapi()

# =========================
# Error Handlers
# =========================
@app.exception_handler(RateLimitExceeded)
async def ratelimit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
