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
load_dotenv()

# Logging setup
log_file = "app.log"
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=3)
log_handler.setFormatter(log_formatter)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# Environment variables
TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
AUTH_URL = os.getenv("AUTH_URL", f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize")
TOKEN_URL = os.getenv("TOKEN_URL", f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token")
API_AUDIENCE = os.getenv("API_AUDIENCE", CLIENT_ID)
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"

# FastAPI instance
app = FastAPI(
    title="Secure API with Azure AD",
    description="API demonstrating free-tier security controls and OWASP vulnerabilities",
    version="1.0.0"
)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# OAuth2 scheme
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=AUTH_URL,
    tokenUrl=TOKEN_URL,
    scopes={"api://your-api-client-id/access_as_user": "Access API as a user"}
)

# Fetch JWKS
def get_jwks():
    resp = requests.get(JWKS_URL)
    resp.raise_for_status()
    return resp.json()

jwks = get_jwks()

# JWT verification
def verify_token(token: str):
    try:
        header_b64, payload_b64, signature_b64 = token.split('.')
        signed_message = f"{header_b64}.{payload_b64}"
        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")

        if not kid:
            raise HTTPException(status_code=401, detail="Token missing kid header")

        key = next((k for k in jwks["keys"] if k["kid"] == kid), None)
        if not key:
            raise HTTPException(status_code=401, detail="Appropriate key not found")

        public_key = jwk.construct(key)
        if not public_key.verify(signed_message.encode(), jwt.base64url_decode(signature_b64.encode())):
            raise HTTPException(status_code=401, detail="Signature verification failed")

        payload = jwt.decode(
            token,
            public_key.to_pem().decode(),
            algorithms=[key["alg"]],
            audience=API_AUDIENCE
        )
        return payload

    except (JWTError, JWKError) as e:
        logger.error(f"JWT verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"Unexpected auth error: {e}")
        raise HTTPException(status_code=500, detail="Internal auth error")

# Request model
class SecureDataRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    email: EmailStr
    comment: str = Field(None, max_length=500)

# Simulated user DB
fake_users = {
    "user1": {"id": "user1", "username": "alice", "email": "alice@example.com"},
    "user2": {"id": "user2", "username": "bob", "email": "bob@example.com"}
}

# Routes
@app.get("/", summary="API Health Check")
def root():
    return {"message": "API is up and running"}

@app.get("/secure-data", summary="Admin-only secure data")
@limiter.limit("5/minute")
async def secure_data(request: Request, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    roles = payload.get("roles") or []
    if "Admin" not in roles:
        raise HTTPException(status_code=403, detail="User lacks required role")
    logger.info(f"User {payload.get('preferred_username')} accessed secure data")
    return {"message": "Secure data accessed!", "token_payload": payload}

@app.post("/submit-data", summary="Submit user data")
@limiter.limit("10/minute")
async def submit_data(request: Request, data: SecureDataRequest, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    logger.info(f"User {payload.get('preferred_username')} submitted data: {data.dict()}")
    return {"message": "Data received successfully", "submitted_data": data.dict()}

@app.get("/users/{user_id}", summary="Simulate BOLA vulnerability")
@limiter.limit("5/minute")
async def get_user(user_id: str, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    user = fake_users.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    logger.warning(f"[BOLA] {payload.get('preferred_username')} accessed data for {user_id}")
    return user

@app.get("/openapi.json", include_in_schema=False)
async def openapi_json():
    return app.openapi()

# Rate limit error
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
