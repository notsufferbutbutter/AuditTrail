"""Check the Microsoft Entra access token that the browser sends when logging in."""

import jwt
from fastapi import HTTPException
from jwt import PyJWKClient

from backend.config import Settings

REQUIRED_CLAIMS = ["exp", "iat", "nbf", "iss", "aud", "tid", "oid", "sub"]


class EntraTokens:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.keys = PyJWKClient(
            f"https://login.microsoftonline.com/{settings.tenant_id}/discovery/v2.0/keys",
            timeout=10,
        )

    def identity(self, token: str) -> str:
        """Return the user's name if the token is valid, otherwise raise an HTTP error."""
        config = self.settings
        try:
            # Entra can issue v1 or v2 tokens, which differ in issuer, audience and client claim.
            # The version is read before verification only to choose the matching rules.
            version = jwt.decode(token, options={"verify_signature": False}).get("ver")
            if version == "2.0":
                issuer = f"https://login.microsoftonline.com/{config.tenant_id}/v2.0"
                audience = config.backend_client_id
                client_claim = "azp"
            elif version == "1.0":
                issuer = f"https://sts.windows.net/{config.tenant_id}/"
                audience = f"api://{config.backend_client_id}"
                client_claim = "appid"
            else:
                raise jwt.InvalidTokenError("Unsupported token version")

            key = self.keys.get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, key, algorithms=["RS256"], audience=audience,
                                issuer=issuer, options={"require": REQUIRED_CLAIMS})

            if claims["tid"] != config.tenant_id or claims.get(client_claim) != config.frontend_client_id:
                raise jwt.InvalidTokenError("Unexpected tenant or client")
            if "access_as_user" not in claims.get("scp", "").split():
                raise HTTPException(status_code=403, detail="Required access_as_user scope missing")

            return claims.get("preferred_username") or claims.get("email") or claims["oid"]
        except jwt.PyJWKClientConnectionError:
            raise HTTPException(status_code=503, detail="Microsoft sign-in is temporarily unavailable") from None
        except (jwt.PyJWTError, ValueError, TypeError, KeyError):
            raise HTTPException(status_code=401, detail="Invalid Microsoft access token",
                                headers={"WWW-Authenticate": "Bearer"}) from None
