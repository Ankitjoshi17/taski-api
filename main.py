# main.py
import os
import logging
from logging.handlers import RotatingFileHandler
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr
from jose import jwt, jwk
from jose.exceptions import JWTError, JWKError
from dotenv import load_dotenv
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import base64
import requests

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

app = FastAPI(title="Secure API with OWASP Vulnerabilities")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=AUTH_URL,
    tokenUrl=TOKEN_URL,
    scopes={"access_as_user": "Access API as user"}
)

# Simulated DB
users_db = {
    "user1": {"id": "user1", "username": "alice", "email": "alice@example.com", "role": "Admin", "password": "123456"},
    "user2": {"id": "user2", "username": "bob", "email": "bob@example.com", "role": "User", "password": "password"},
}

# JWKS cache
jwks = requests.get(JWKS_URL).json()

# JWT Verification
def verify_token(token: str):
    try:
        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Token missing kid")

        key_data = next((k for k in jwks["keys"] if k["kid"] == kid), None)
        if not key_data:
            raise HTTPException(status_code=401, detail="No matching key")

        public_key = jwk.construct(key_data, algorithm="RS256")

        message, encoded_sig = token.rsplit('.', 1)
        decoded_sig = base64.urlsafe_b64decode(encoded_sig + "==")
        if not public_key.verify(message.encode(), decoded_sig):
            raise HTTPException(status_code=401, detail="Signature check failed")

        payload = jwt.decode(
            token,
            public_key.to_pem().decode(),
            algorithms=["RS256"],
            audience=API_AUDIENCE,
            issuer=f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
        )
        return payload
    except Exception as e:
        logger.error(f"JWT verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")

# Schemas
class SecureDataRequest(BaseModel):
    username: str
    email: EmailStr
    comment: str | None = Field(None, max_length=500)

class MassAssignmentModel(BaseModel):
    username: str
    email: EmailStr
    is_admin: bool | None = False  # Attacker might try to manipulate this

@app.get("/")
def root():
    return {"message": "API running"}

@app.get("/secure-data")
@limiter.limit("5/minute")
def secure_data(request: Request, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    roles = payload.get("roles", [])
    if "Admin" not in roles:
        raise HTTPException(status_code=403, detail="Admin role required")
    return {"message": "Secure data", "user": payload.get("preferred_username")}

@app.post("/submit-data")
@limiter.limit("10/minute")
def submit_data(request: Request, data: SecureDataRequest, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    return {"message": "Data submitted", "data": data.dict()}

@app.get("/users/{user_id}")
@limiter.limit("5/minute")
def get_user(request: Request, user_id: str, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    user = users_db.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user  # BOLA vulnerability simulated here

@app.post("/login")  # Broken User Authentication (no rate limit, poor validation)
def login(data: dict):
    user = users_db.get(data.get("username"))
    if user and user["password"] == data.get("password"):
        return {"message": "Logged in"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/public-profile")  # Excessive Data Exposure
def public_profile():
    return users_db  # returns all user data (including password!) without filtering

@app.post("/mass-assign")  # Mass Assignment
def mass_assign(data: dict):
    return {"created_user": data}  # blindly trusts incoming keys

@app.get("/v1/legacy-info")  # Improper Asset Management
def legacy_info():
    return {"version": "v1", "message": "Deprecated endpoint"}

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
