# main.py
import os
import logging
from logging.handlers import RotatingFileHandler
import requests
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr
from jose import jwt, jwk
from jose.exceptions import JWTError, JWKError
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Logging setup
log_file = "app.log"
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=3)
log_handler.setFormatter(log_formatter)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# Environment config
TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
API_AUDIENCE = os.getenv("API_AUDIENCE", CLIENT_ID)

AUTH_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"

# FastAPI setup
app = FastAPI(
    title="Secure API with Azure AD",
    description="API with OAuth2 and BOLA simulation",
    version="1.0.0"
)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# OAuth2 Bearer config
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=AUTH_URL,
    tokenUrl=TOKEN_URL,
    scopes={"access_as_user": "Access API as user"}
)

# Simulated in-memory user DB
fake_users = {
    "user1": {"id": "user1", "username": "alice", "email": "alice@example.com"},
    "user2": {"id": "user2", "username": "bob", "email": "bob@example.com"},
}

# JWKS cache
jwks = requests.get(JWKS_URL).json()

# JWT verification
def verify_token(token: str):
    try:
        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Token missing 'kid' header")

        key_data = next((key for key in jwks["keys"] if key["kid"] == kid), None)
        if not key_data:
            raise HTTPException(status_code=401, detail="Public key not found in JWKS")

        public_key = jwk.construct(key_data, algorithm="RS256")  # 🔧 Explicit algorithm

        payload = jwt.decode(
            token,
            public_key.to_pem().decode("utf-8"),
            algorithms=["RS256"],
            audience="cc4ff219-81a0-4f5e-a3ca-bc92b67eea3c",
            issuer=f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
        )
        return payload

    except (JWTError, JWKError) as e:
        logger.error(f"JWT verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=401, detail="Internal auth error")

# Request model
class SecureDataRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    comment: str | None = Field(None, max_length=500)

# Routes
@app.get("/", summary="Health check")
def root():
    return {"message": "API is running"}

@app.get("/secure-data", summary="Admin-only secure data")
@limiter.limit("5/minute")
async def secure_data(request: Request, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    roles = payload.get("roles", [])
    if "Admin" not in roles:
        raise HTTPException(status_code=403, detail="Admin role required")
    logger.info(f"{payload.get('preferred_username')} accessed secure data")
    return {"message": "Secure data accessed", "user": payload.get("preferred_username")}

@app.post("/submit-data", summary="Submit user data")
@limiter.limit("10/minute")
async def submit_data(request: Request, data: SecureDataRequest, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    logger.info(f"{payload.get('preferred_username')} submitted: {data.dict()}")
    return {"message": "Data received", "submitted": data.dict()}

@app.get("/users/{user_id}", summary="Simulate BOLA vulnerability")
@limiter.limit("5/minute")
async def get_user(request: Request, user_id: str, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    user = fake_users.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    logger.warning(f"[BOLA] {payload.get('preferred_username')} accessed user {user_id}")
    return user

@app.get("/openapi.json", include_in_schema=False)
async def openapi_json():
    return app.openapi()

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
