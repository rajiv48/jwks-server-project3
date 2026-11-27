
"""FastAPI application exposing JWKS, authentication, and registration endpoints."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta

import jwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from jwks_server.auth_logs import log_auth_request
from jwks_server.keys import KeyRecord, KeyStore
from jwks_server.users import register_user


JWKS_PATH = "/.well-known/jwks.json"
AUTH_PATH = "/auth"
TOKEN_TTL = timedelta(minutes=30)
MOCK_SUBJECT = "userABC"
ALGORITHM = "RS256"


class RegistrationRequest(BaseModel):
    username: str
    email: str


def issue_token(record: KeyRecord, now: datetime, *, expired: bool) -> str:
    """Generate a signed JWT."""

    if expired:
        exp = record.expires_at
        iat = exp - TOKEN_TTL
    else:
        iat = now
        exp = min(now + TOKEN_TTL, record.expires_at)

    claims = {
        "sub": MOCK_SUBJECT,
        "iat": int(iat.timestamp()),
        "exp": int(exp.timestamp()),
    }

    return jwt.encode(
        claims,
        record.private_key,
        algorithm=ALGORITHM,
        headers={"kid": record.kid},
    )


def create_app(store: KeyStore | None = None) -> FastAPI:
    """Build the FastAPI application."""

    key_store = store if store is not None else KeyStore()

    app = FastAPI(
        title="JWKS Server",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get(JWKS_PATH)
    def jwks() -> dict[str, list[dict[str, str]]]:
        """Return all unexpired public keys."""

        return {
            "keys": [
                key.to_jwk()
                for key in key_store.unexpired_keys()
            ]
        }

    @app.post(AUTH_PATH, response_class=PlainTextResponse)
    async def auth(request: Request) -> str:
        """Mock-authenticate the caller and log the request."""

        username = None

        # Extract username from the JSON request body.
        try:
            details = await request.json()

            if isinstance(details, dict):
                username = details.get("username")

                if not isinstance(username, str):
                    username = None

        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        # Retrieve the client's IP address.
        request_ip = request.client.host if request.client else "unknown"

        # Select the appropriate RSA key.
        expired = "expired" in request.query_params

        if expired:
            record = key_store.expired_key()
        else:
            record = key_store.active_key()

        # Generate the signed JWT.
        token = issue_token(
            record,
            key_store.now(),
            expired=expired,
        )

        # Record the successful request in SQLite.
        log_auth_request(
            request_ip,
            username,
            key_store._db_path,
        )

        return token

    @app.post("/register", status_code=201)
    def register(details: RegistrationRequest):
        """Register a new user."""

        if not details.username.strip() or not details.email.strip():
            raise HTTPException(
                status_code=400,
                detail="Username and email are required",
            )

        try:
            password = register_user(
                details.username,
                details.email,
                key_store._db_path,
            )

        except sqlite3.IntegrityError as error:
            raise HTTPException(
                status_code=409,
                detail="Username or email already exists",
            ) from error

        return {"password": password}

    return app
