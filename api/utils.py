import requests
import logging

from typing import Dict
from fastapi import HTTPException
from jose import jwt, JWTError
from jose.utils import base64url_decode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

ALGORITHM = "RS256"

def jwks_to_pem(jwks_key: Dict) -> str:
    try:
        logger.debug(f"Converting JWKS key: {jwks_key}")
        modulus = int.from_bytes(base64url_decode(jwks_key['n'].encode()), 'big')
        exponent = int.from_bytes(base64url_decode(jwks_key['e'].encode()), 'big')

        public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        logger.debug("Successfully converted JWKS to PEM.")
        return pem.decode('utf-8')
    except Exception as e:
        logger.error(f"Error converting JWKS to PEM: {e}")
        raise RuntimeError(f"Error converting JWKS to PEM: {e}")


def decode_jwt(token: str, keys, client_id) -> Dict:
    try:
        logger.debug(f"Decoding token: {token}")
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        logger.info(f"Token header: {header}")

        if not kid or kid not in keys:
            logger.error(f"Key ID {kid} not found in loaded keys.")
            raise HTTPException(status_code=401, detail="Invalid token: Unknown Key ID")

        public_key = keys[kid]
        logger.info(f"Using public key with kid: {kid}")

        payload = jwt.decode(
            token,
            public_key,
            algorithms=[ALGORITHM],
            audience=client_id
        )
        logger.info(f"Token decoded successfully: {payload}")
        return payload
    except JWTError as e:
        logger.error(f"JWT decoding error: {e}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

def fetch_keycloak_public_keys(url, realm) -> Dict[str, str]:
    try:
        jwks_url = f"{url}/realms/{realm}/protocol/openid-connect/certs"
        logger.info(f"Fetching JWKS from {jwks_url}")
        response = requests.get(jwks_url, timeout=10)
        response.raise_for_status()
        jwks = response.json()
        logger.debug(f"JWKS response: {jwks}")

        keys = {}
        for key in jwks.get("keys", []):
            if key.get("use") == "sig":  # Only use signing keys
                keys[key["kid"]] = jwks_to_pem(key)
        if not keys:
            raise RuntimeError("No signing keys ('use': 'sig') found in JWKS endpoint")
        logger.info(f"Fetched {len(keys)} signing keys.")
        return keys
    except Exception as e:
        logger.error(f"Failed to fetch public keys from Keycloak: {e}")
        raise RuntimeError(f"Failed to fetch public keys from Keycloak: {e}")
