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

# --- Logging Configuration ---
# Configures a rotating file handler for application logs.
# Logs will be written to 'app.log', with a maximum size of 1MB (1_000_000 bytes)
# and up to 3 backup files. This helps manage log file size over time.
log_file = "app.log"
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=3)
log_handler.setFormatter(log_formatter)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) # Set logging level to INFO
logger.addHandler(log_handler) # Add the rotating file handler

# --- Environment Variables ---
# Loads necessary environment variables for Azure AD integration.
# These should be set in your deployment environment or a .env file for local development.
TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
# Default URLs are constructed using TENANT_ID if not explicitly provided
AUTH_URL = os.getenv("AUTH_URL", f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize")
TOKEN_URL = os.getenv("TOKEN_URL", f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token")
API_AUDIENCE = os.getenv("API_AUDIENCE", CLIENT_ID) # Audience for JWT validation
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys" # URL to fetch public keys

# --- FastAPI Initialization ---
# Initializes the FastAPI application with global OpenAPI (Swagger) metadata.
# This metadata will be visible in the auto-generated documentation (/docs or /redoc).
app = FastAPI(
    title="Secure API with Azure AD",
    description="OAuth2-protected API with FastAPI, rate limiting, and security controls. Simulates API vulnerabilities for testing.",
    version="1.0.0"
)

# --- Rate Limiting Configuration ---
# Initializes the rate limiter using 'slowapi' library.
# 'get_remote_address' is used to identify clients by their IP address.
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter # Attach limiter to app state
app.add_middleware(SlowAPIMiddleware) # Add the rate limiting middleware to FastAPI

# --- OAuth2 Configuration ---
# Defines the OAuth2 scheme for token authentication.
# This specifies where to get authorization and tokens, and the required scopes.
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=AUTH_URL,
    tokenUrl=TOKEN_URL,
    scopes={"api://your-api-client-id/access_as_user": "Access API as a user"}
)

# --- Fetch JWKS (JSON Web Key Set) ---
# Function to retrieve the public keys from Azure AD's JWKS endpoint.
# These keys are used to verify the digital signature of incoming JWTs.
def get_jwks():
    response = requests.get(JWKS_URL)
    response.raise_for_status() # Raise an exception for bad status codes
    return response.json()

jwks = get_jwks() # Load JWKS at application startup

# --- Verify JWT Token Function ---
# Custom function to verify the authenticity and integrity of a JWT.
# It checks the token's signature against the fetched JWKS, and decodes the payload.
def verify_token(token: str):
    try:
        # Split token into its three parts: header, payload, signature
        header_b64, payload_b64, signature_b64 = token.split('.')
        signed_message = f"{header_b64}.{payload_b64}" # Part of the token that was signed
        headers = jwt.get_unverified_header(token) # Get header without verifying signature
        kid = headers.get("kid") # Key ID from the token header

        if not kid:
            raise HTTPException(status_code=401, detail="Token missing kid header")

        # Find the public key in JWKS that matches the token's kid
        key = next((key for key in jwks["keys"] if key["kid"] == kid), None)
        if not key:
            raise HTTPException(status_code=401, detail="Appropriate key not found")

        public_key = jwk.construct(key) # Construct the public key object

        # Verify the token's signature
        if not public_key.verify(
            signed_message.encode("utf-8"),
            jwt.base64url_decode(signature_b64.encode("utf-8"))
        ):
            raise HTTPException(status_code=401, detail="Signature verification failed")

        # Decode the token payload after successful signature verification
        payload = jwt.decode(
            token,
            public_key.to_pem().decode(), # Public key in PEM format
            algorithms=[key["alg"]],      # Algorithm used for signing
            audience=API_AUDIENCE         # Verify the audience claim
        )
        return payload

    except (JWTError, JWKError) as e:
        logger.error(f"JWT verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")

    except Exception as e:
        logger.error(f"Unexpected error verifying token: {e}")
        raise HTTPException(status_code=500, detail="Internal authentication error")

# --- Pydantic Models for Request Body Validation ---
# Defines the schema and validation rules for incoming data to the /submit-data endpoint.
class SecureDataRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    email: EmailStr # Ensures valid email format
    comment: str = Field(None, max_length=500) # Optional field with max length

# --- Simulated In-Memory User Database ---
# A simple dictionary to simulate user data storage for the BOLA vulnerability.
fake_users = {
    "45069c09-5c39-4a31-b59f-faad1d5ec4b5": {"id": "45069c09-5c39-4a31-b59f-faad1d5ec4b5", "name": "Alice", "email": "alice@example.com"},
    "6244c043-f7e2-4311-9158-893e7d5434c2": {"id": "6244c043-f7e2-4311-9158-893e7d5434c2", "name": "Bob", "email": "bob@example.com", "sensitive_info": "bob_secret_project_details"}
}

# --- API Endpoints ---

@app.get("/", summary="API Health Check", description="Checks if the API is up and running. No authentication required.")
def root():
    return {"message": "API is up and running"}

@app.get("/secure-data", summary="Admin-only Secure Data", description="This endpoint requires a valid JWT with the 'Admin' role. It simulates access to highly sensitive data.")
@limiter.limit("5/minute") # Apply rate limiting to this endpoint
async def secure_data(request: Request, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    roles = payload.get("roles", []) # Get roles from the JWT payload
    if "Admin" not in roles:
        raise HTTPException(status_code=403, detail="User does not have required role")

    logger.info(f"User {payload.get('preferred_username')} accessed secure data")
    return {"message": "Secure data accessed!", "token_payload": payload}

@app.post("/submit-data", summary="Submit User Data", description="Allows authenticated users to submit data. Includes input validation and rate limiting to prevent common attacks like injection.")
@limiter.limit("10/minute") # Apply rate limiting to this endpoint
async def submit_data(request: Request, data: SecureDataRequest, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    logger.info(f"User {payload.get('preferred_username')} submitted data: {data.dict()}")
    return {"message": "Data received successfully", "submitted_data": data.dict()}

@app.get("/users/{user_id}", summary="Simulated Broken Object Level Authorization (BOLA)", description="⚠️ **Intentionally Vulnerable:** This endpoint allows any authenticated user to retrieve data for *any* user_id by manipulating the path parameter. It demonstrates a Broken Object Level Authorization (BOLA) vulnerability as it lacks proper ownership checks.")
@limiter.limit("5/minute") # Apply rate limiting to this endpoint
async def get_user_data(user_id: str, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    current_user_oid = payload.get("oid") # Assuming 'oid' is the unique identifier for the current user

    user = fake_users.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # This is the BOLA vulnerability: It returns the user data without checking
    # if the 'user_id' requested matches the 'current_user_oid' from the token.
    logger.warning(f"[BOLA SIMULATION] User '{payload.get('preferred_username')}' (OID: {current_user_oid}) accessed data for user ID: '{user_id}' (vulnerable access).")
    return user

@app.get("/openapi.json", include_in_schema=False, summary="OpenAPI Specification Export", description="Exports the full OpenAPI (Swagger) specification for the API. This is crucial for automated security testing tools like OWASP ZAP to understand the API structure and generate targeted test cases.")
async def get_openapi_json():
    return app.openapi()

# --- Exception Handlers ---
# Custom exception handler for rate limit exceeded errors.
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded"}
    )

# --- How to Run the App (for local development) ---
# To run this application locally, ensure you have uvicorn installed (`pip install uvicorn`).
# Then, execute the following command in your terminal:
# uvicorn main:app --reload
# Make sure your environment variables (TENANT_ID, CLIENT_ID, API_AUDIENCE) are set
# or use a .env file with 'python-dotenv'.
