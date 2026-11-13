"""Tests for the Entra token check. The tokens are signed with a test key, Microsoft is not contacted."""

import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from backend.config import Settings
from backend.entra import EntraTokens

settings = Settings(origin="https://audittrail.example.com")
EMAIL = "person@example.com"


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def entra(key):
    entra = EntraTokens(settings)
    entra.keys.get_signing_key_from_jwt = lambda token: SimpleNamespace(key=key.public_key())
    return entra


def make_token(key, **overrides):
    now = int(time.time())
    claims = {
        "ver": "2.0", "iss": f"https://login.microsoftonline.com/{settings.tenant_id}/v2.0",
        "aud": settings.backend_client_id, "tid": settings.tenant_id,
        "azp": settings.frontend_client_id, "scp": "access_as_user",
        "oid": "user-object-id", "sub": "user-subject", "preferred_username": EMAIL,
        "exp": now + 600, "nbf": now - 10, "iat": now - 10,
    }
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="RS256")


def test_valid_token(entra, key):
    assert entra.identity(make_token(key)) == EMAIL


def test_valid_v1_token(entra, key):
    token = make_token(key, ver="1.0", appid=settings.frontend_client_id,
                       iss=f"https://sts.windows.net/{settings.tenant_id}/",
                       aud=f"api://{settings.backend_client_id}")
    assert entra.identity(token) == EMAIL


@pytest.mark.parametrize("overrides,status", [
    ({"aud": "another-api"}, 401),
    ({"iss": "https://attacker.example.com"}, 401),
    ({"tid": "another-tenant"}, 401),
    ({"azp": "another-client"}, 401),
    ({"exp": 1}, 401),
    ({"nbf": 9999999999}, 401),
    ({"scp": "other_scope"}, 403),
    ({"scp": ""}, 403),
    ({"ver": "3.0"}, 401),
])
def test_rejects_invalid_claims(entra, key, overrides, status):
    with pytest.raises(HTTPException) as error:
        entra.identity(make_token(key, **overrides))
    assert error.value.status_code == status


def test_rejects_token_signed_with_another_key(entra):
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(HTTPException) as error:
        entra.identity(make_token(attacker_key))
    assert error.value.status_code == 401


def test_rejects_garbage(entra):
    with pytest.raises(HTTPException) as error:
        entra.identity("not-a-token")
    assert error.value.status_code == 401
