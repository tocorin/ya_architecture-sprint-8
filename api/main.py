import os
import logging

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware

from utils import decode_jwt, fetch_keycloak_public_keys


# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# FastAPI app instance
app = FastAPI()

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Keycloak configuration
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
REALM_NAME = os.getenv("KEYCLOAK_REALM", "reports-realm")
ROLE_REQUIRED = "prothetic_user"
CLIENT_ID = os.getenv("CLIENT_ID", "reports-api")

KEYCLOAK_PUBLIC_KEYS = {}

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@app.on_event("startup")
def load_keycloak_public_keys():
    global KEYCLOAK_PUBLIC_KEYS
    try:
        KEYCLOAK_PUBLIC_KEYS = fetch_keycloak_public_keys(KEYCLOAK_URL, REALM_NAME)
        logger.info("Public keys loaded successfully.")
    except RuntimeError as e:
        logger.error(f"Error during Keycloak public key loading: {e}")
        raise


def validate_user_role(token: str = Depends(oauth2_scheme)):
    logger.info("Validating user role.")
    payload = decode_jwt(token, KEYCLOAK_PUBLIC_KEYS, CLIENT_ID)
    roles = payload.get("realm_access", {}).get("roles", [])
    logger.debug(f"User roles: {roles}")
    if not roles or ROLE_REQUIRED not in roles:
        logger.warning("User does not have the required role.")
        raise HTTPException(status_code=403, detail="Insufficient role")


@app.get("/reports")
def get_report(validate: None = Depends(validate_user_role)):
    logger.info("Authorized user requesting report.")
    return {"report": "This is a very important report"}
