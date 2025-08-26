# main.py
import os
import logging
from logging.handlers import RotatingFileHandler
from typing import Optional, Dict, Any

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
# Environment / Config
# =========================
load_dotenv()

# Auth modes: "dev" (no Azure token; use X-Dev-User header), or "azure"
AUTH_MODE = os.getenv("AUTH_MODE", "dev").lower()

TENANT_ID = os.getenv("TENANT_ID")  # required for AUTH_MODE=azure
CLIENT_ID = os.getenv("CLIENT_ID")  # your Azure App (API) client id
API_AUDIENCE = os.getenv("API_AUDIENCE", CLIENT_ID)

AUTH_URL = (
    f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize"
    if TENANT_ID else None
)
TOKEN_URL = (
    f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    if TENANT_ID else None
)
JWKS_URL = (
    f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
    if TENANT_ID else None
)

# Vulnerability toggles (defaults make local testing easy)
VULN_BOLA = os.getenv("VULN_BOLA", "true").lower() == "true"                  # if true: /users/{id} allows cross-user access
VULN_LEAK = os.getenv("VULN_LEAK", "true").lower() == "true"                  # if true: /leak-data exposes sensitive fields
VULN_MASS_ASSIGN = os.getenv("VULN_MASS_ASSIGN", "true").lower() == "true"    # if true: /mass-assign blindly accepts fields
LOGIN_RATE_LIMIT = os.getenv("LOGIN_RATE_LIMIT", "true").lower() == "true"    # limit login attempts (mitigation)
SECURITY_HEADERS = os.getenv("SECURITY_HEADERS", "true").lower() == "true"    # add standard security headers

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
    title="Secure API (Local Testing Build)",
    description="FastAPI app with intentional vulns + toggles for MSc project",
    version="1.0.0",
)

# SlowAPI limiter requires the middleware + `request: Request` arg on routes you decorate
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# =========================
# Security Headers Middleware
# =========================
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    if SECURITY_HEADERS:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=()"
        )
        # CSP normally for HTML, not JSON APIs
        # response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none';")
    return response

# =========================
# OAuth2 scheme (only used in Azure mode)
# =========================
oauth2_scheme = None
if AUTH_MODE == "azure":
    if not (TENANT_ID and CLIENT_ID and API_AUDIENCE and AUTH_URL and TOKEN_URL and JWKS_URL):
        logger.error("Missing Azure env vars; cannot run AUTH_MODE=azure.")
        raise RuntimeError("Missing Azure env vars for AUTH_MODE=azure.")
    oauth2_scheme = OAuth2AuthorizationCodeBearer(
        authorizationUrl=AUTH_URL,
        tokenUrl=TOKEN_URL,
        scopes={"access_as_user": "Access API as user"},
    )
    try:
        resp = requests.get(JWKS_URL, timeout=10)
        resp.raise_for_status()
        JWKS = resp.json()
    except Exception as e:
        logger.error(f"Failed to fetch JWKS: {e}")
        JWKS = {"keys": []}
else:
    JWKS = {"keys": []}  # not used in dev mode

# =========================
# Simulated Users (for dev + demo)
# =========================
USERS_DB: Dict[str, Dict[str, Any]] = {
    "user1": {"id": "user1", "username": "alice", "email": "alice@example.com", "role": "Admin", "password": "123456"},
    "user2": {"id": "user2", "username": "bob", "email": "bob@example.com", "role": "User", "password": "password"},
}
EMAIL_TO_ID = {"alice@example.com": "user1", "bob@example.com": "user2"}

# =========================
# Auth helpers
# =========================
def get_user_from_dev_header(request: Request) -> Dict[str, Any]:
    """
    Dev-mode auth: pass a header like `X-Dev-User: user1|Admin`
    """
    header = request.headers.get("X-Dev-User")
    if not header:
        raise HTTPException(status_code=401, detail="Missing X-Dev-User; expected 'userId|Role' in dev mode")
    try:
        user_id, role = header.split("|", 1)
        user = USERS_DB.get(user_id)
        if not user:
            raise HTTPException(status_code=401, detail="Unknown dev user")
        return {"sub": user_id, "oid": user_id, "preferred_username": user["email"], "roles": [role]}
    except ValueError:
        raise HTTPException(status_code=400, detail="X-Dev-User format must be 'userId|Role'")

def get_user_from_azure_token(token: str) -> Dict[str, Any]:
    """
    Azure mode: validate JWT using JWKS, audience, and issuer.
    """
    try:
        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Token missing 'kid'")

        key_data = next((k for k in JWKS.get("keys", []) if k.get("kid") == kid), None)
        if not key_data:
            raise HTTPException(status_code=401, detail="No matching key in JWKS")

        # Explicitly pass the algorithm; Azure JWKS often omits "alg"
        public_key = jwk.construct(key_data, algorithm="RS256")

        payload = jwt.decode(
            token,
            public_key.to_pem().decode(),
            algorithms=["RS256"],
            audience=API_AUDIENCE,  # IMPORTANT: should be GUID (not api://…)
            issuer=f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
            options={"require_aud": True, "require_iat": True, "require_exp": True},
        )
        return payload
    except (JWTError, JWKError) as e:
        logger.error(f"JWT verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"Unexpected auth error: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme) if AUTH_MODE == "azure" else None
):
    if AUTH_MODE == "dev":
        return get_user_from_dev_header(request)
    # Azure mode
    if not token:
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    return get_user_from_azure_token(token)

# =========================
# Schemas
# =========================
class SecureDataRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    email: EmailStr
    comment: Optional[str] = Field(None, max_length=500)

class MassAssignPatched(BaseModel):
    model_config = ConfigDict(extra="forbid")  # forbid unexpected fields
    username: str
    email: EmailStr
    # No is_admin / role here — cannot be injected by client

# =========================
# Routes
# =========================
@app.get("/", summary="Health")
def root():
    return {"message": "API running (local)", "auth_mode": AUTH_MODE}

@app.get("/_status", summary="Show toggles")
def status_view():
    return {
        "AUTH_MODE": AUTH_MODE,
        "VULN_BOLA": VULN_BOLA,
        "VULN_LEAK": VULN_LEAK,
        "VULN_MASS_ASSIGN": VULN_MASS_ASSIGN,
        "LOGIN_RATE_LIMIT": LOGIN_RATE_LIMIT,
        "SECURITY_HEADERS": SECURITY_HEADERS,
    }

# ------- Broken User Authentication (weak) -------
if LOGIN_RATE_LIMIT:
    @app.post("/login", summary="Weak login (limited)")
    @limiter.limit("10/minute")
    def login_limited(request: Request, data: Dict[str, str]):
        user = USERS_DB.get(data.get("username"))
        if user and user["password"] == data.get("password"):
            return {"message": "Logged in", "token": f"fake.{user['id']}.token"}
        raise HTTPException(status_code=401, detail="Invalid credentials")
else:
    @app.post("/login", summary="Weak login (no rate limit)")
    def login_unlimited(data: Dict[str, str]):
        user = USERS_DB.get(data.get("username"))
        if user and user["password"] == data.get("password"):
            return {"message": "Logged in", "token": f"fake.{user['id']}.token"}
        raise HTTPException(status_code=401, detail="Invalid credentials")

# ------- Secure data (RBAC Admin) -------
@app.get("/secure-data", summary="Admin-only secure data")
@limiter.limit("5/minute")
def secure_data(request: Request, user=Depends(get_current_user)):
    roles = user.get("roles") or []
    if "Admin" not in roles:
        raise HTTPException(status_code=403, detail="Admin role required")
    logger.info(f"{user.get('preferred_username')} accessed /secure-data")
    return {"message": "Secure data", "user": user.get("preferred_username")}

# ------- BOLA: /users/{user_id} -------
@app.get("/users/{user_id}", summary="Get user (BOLA demo)")
@limiter.limit("5/minute")
def get_user_by_id(request: Request, user_id: str, user=Depends(get_current_user)):
    record = USERS_DB.get(user_id)
    if not record:
        raise HTTPException(status_code=404, detail="User not found")

    if VULN_BOLA:
        # Vulnerable path: returns any user to any authenticated user
        logger.warning(f"[BOLA-VULN] {user.get('preferred_username')} accessed {user_id}")
        return record
    else:
        # Patched: enforce ownership (map token -> permitted id)
        caller_email = user.get("preferred_username")
        caller_id = EMAIL_TO_ID.get(caller_email, user.get("oid") or user.get("sub"))
        if caller_id != user_id and "Admin" not in (user.get("roles") or []):
            raise HTTPException(status_code=403, detail="Forbidden (ownership check)")
        return record

# ------- Excessive Data Exposure -------
@app.get("/leak-data", summary="Excessive Data Exposure demo")
def leak_data():
    if VULN_LEAK:
        return {
            "id": "user2",
            "username": "bob",
            "email": "bob@example.com",
            "password": "pbkdf2_sha256$fake-hash",
            "role": "Admin",
            "auth_token": "xyz.jwt.token",
            "debug_info": {"request_ip": "192.168.1.5", "processing_time": "120ms"},
        }
    # Patched response
    return {
        "id": "user2",
        "username": "bob",
        "email": "bob@example.com",
        "role": "User",
        "note": "Sensitive fields removed by server policy",
    }

# ------- Mass Assignment -------
@app.post("/mass-assign", summary="Mass Assignment (vuln or patched via toggle)")
def mass_assign(data: Dict[str, Any]):
    if VULN_MASS_ASSIGN:
        # Vulnerable: blindly trusts incoming keys
        return {"created_user": data}
    # Patched: only whitelisted fields allowed
    parsed = MassAssignPatched(**data)
    safe = parsed.model_dump()
    safe["role"] = "User"  # server-controlled defaults
    safe["is_admin"] = False
    return {"created_user": safe}

# ------- Improper Asset Management -------
@app.get("/v1/legacy-info", summary="Deprecated endpoint")
def legacy_info_v1():
    # Patched: return 410 Gone + guidance
    return JSONResponse(
        status_code=status.HTTP_410_GONE,
        content={"message": "Deprecated. Use /v2/info"},
    )

@app.get("/v2/info", summary="Current versioned endpoint")
def info_v2():
    return {"version": "v2", "status": "ok"}

# ------- Submit Data (validated + rate-limited) -------
@app.post("/submit-data", summary="Submit user data (validated)")
@limiter.limit("10/minute")
def submit_data(request: Request, payload: SecureDataRequest, user=Depends(get_current_user)):
    logger.info(f"{user.get('preferred_username')} submitted data {payload.model_dump()}")
    return {"message": "Data received", "submitted": payload.model_dump()}

# OpenAPI for ZAP import
@app.get("/openapi.json", include_in_schema=False)
def openapi_spec():
    return app.openapi()

# Rate limit handler
@app.exception_handler(RateLimitExceeded)
async def ratelimit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
