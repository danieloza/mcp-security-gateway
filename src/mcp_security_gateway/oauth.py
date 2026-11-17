"""OAuth 2.1 resource-server mode (MCP authorization, revision 2025-11-25).

The gateway validates access tokens issued by an external authorization server.
It never issues tokens, never registers clients and never forwards a client's
token: an accepted token is reduced to the gateway user it maps to.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import jwt
from jwt import PyJWKClient, PyJWKSet
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

MCP_SCOPE = "mcp:tools"
CONSOLE_SCOPE = "gateway:console"
SUPPORTED_SCOPES = (MCP_SCOPE, CONSOLE_SCOPE)
METADATA_PREFIX = "/.well-known/oauth-protected-resource"

# Only asymmetric signatures. A symmetric algorithm would let anyone holding the
# public key mint tokens, and `none` would accept unsigned ones.
ALLOWED_ALGORITHMS = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"})
DEFAULT_ALGORITHMS = ("RS256", "ES256")
CLOCK_SKEW_SECONDS = 30


class OAuthConfigError(RuntimeError):
    """The OAuth settings are missing or unsafe; the gateway refuses to start."""


class TokenRejected(Exception):
    """The access token is not valid for this resource (HTTP 401)."""


class SigningKeysUnavailable(Exception):
    """The authorization server's keys could not be fetched (HTTP 503)."""


@dataclass(frozen=True, slots=True)
class OAuthSettings:
    resource: str
    issuer: str
    authorization_servers: tuple[str, ...]
    jwks_url: str
    subjects: dict[str, str] = field(hash=False)
    algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS

    @property
    def metadata_path(self) -> str:
        # RFC 9728 section 3: the well-known suffix is inserted before the
        # resource's path, so a resource at <origin>/mcp is described at
        # <origin>/.well-known/oauth-protected-resource/mcp.
        return METADATA_PREFIX + urlsplit(self.resource).path

    @property
    def metadata_url(self) -> str:
        parts = urlsplit(self.resource)
        return f"{parts.scheme}://{parts.netloc}{self.metadata_path}"

    def metadata_document(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "authorization_servers": list(self.authorization_servers),
            "scopes_supported": list(SUPPORTED_SCOPES),
            "bearer_methods_supported": ["header"],
            "resource_name": "MCP Security Gateway",
        }


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise OAuthConfigError(f"{name} must be set when MSG_AUTH_MODE=oauth.")
    return value


def _parse_subjects(value: str) -> dict[str, str]:
    subjects: dict[str, str] = {}
    for pair in value.split(","):
        if not pair.strip():
            continue
        subject, sep, user_id = pair.partition("=")
        if not sep or not subject.strip() or not user_id.strip():
            raise OAuthConfigError("MSG_OAUTH_SUBJECTS must be a list of subject=user_id pairs.")
        subjects[subject.strip()] = user_id.strip()
    if not subjects:
        raise OAuthConfigError("MSG_OAUTH_SUBJECTS must map at least one subject to a gateway user.")
    return subjects


def load_oauth_settings() -> OAuthSettings:
    resource = _required("MSG_OAUTH_RESOURCE").rstrip("/")
    parts = urlsplit(resource)
    if parts.scheme not in {"https", "http"} or not parts.netloc or parts.query or parts.fragment:
        raise OAuthConfigError("MSG_OAUTH_RESOURCE must be an absolute http(s) URI without query or fragment.")
    issuer = _required("MSG_OAUTH_ISSUER")
    servers = tuple(
        item.strip() for item in os.getenv("MSG_OAUTH_AUTHORIZATION_SERVERS", issuer).split(",") if item.strip()
    )
    algorithms = tuple(
        item.strip()
        for item in os.getenv("MSG_OAUTH_ALGORITHMS", ",".join(DEFAULT_ALGORITHMS)).split(",")
        if item.strip()
    )
    unsafe = [algorithm for algorithm in algorithms if algorithm not in ALLOWED_ALGORITHMS]
    if unsafe or not algorithms:
        raise OAuthConfigError("MSG_OAUTH_ALGORITHMS may only list asymmetric JWS algorithms.")
    return OAuthSettings(
        resource=resource,
        issuer=issuer,
        authorization_servers=servers,
        jwks_url=_required("MSG_OAUTH_JWKS_URL"),
        subjects=_parse_subjects(_required("MSG_OAUTH_SUBJECTS")),
        algorithms=algorithms,
    )


@dataclass(frozen=True, slots=True)
class VerifiedToken:
    subject: str
    scopes: frozenset[str]


KeySource = Callable[[str], Any]


def static_key_source(jwks: dict[str, Any]) -> KeySource:
    """Resolve signing keys from a fixed JWKS document (tests and offline setups)."""
    key_set = PyJWKSet.from_dict(jwks)

    def resolve(token: str) -> Any:
        kid = jwt.get_unverified_header(token).get("kid")
        for key in key_set.keys:
            if key.key_id == kid:
                return key.key
        raise TokenRejected("Unknown signing key.")

    return resolve


def remote_key_source(jwks_url: str) -> KeySource:
    client = PyJWKClient(jwks_url, cache_keys=True, lifespan=300, timeout=5)

    def resolve(token: str) -> Any:
        try:
            return client.get_signing_key_from_jwt(token).key
        except PyJWKClientConnectionError as exc:
            raise SigningKeysUnavailable("The authorization server's signing keys are unavailable.") from exc
        except PyJWKClientError as exc:
            raise TokenRejected("Unknown signing key.") from exc

    return resolve


class TokenVerifier:
    def __init__(self, settings: OAuthSettings, key_source: KeySource | None = None) -> None:
        self.settings = settings
        self._key_source = key_source or remote_key_source(settings.jwks_url)

    def verify(self, token: str) -> VerifiedToken:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise TokenRejected("Malformed token.") from exc
        # The allowlist comes from configuration, never from the token itself.
        if header.get("alg") not in self.settings.algorithms:
            raise TokenRejected("Signing algorithm is not accepted.")
        key = self._key_source(token)
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=list(self.settings.algorithms),
                audience=self.settings.resource,
                issuer=self.settings.issuer,
                leeway=CLOCK_SKEW_SECONDS,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
        except jwt.InvalidTokenError as exc:
            raise TokenRejected("Token validation failed.") from exc
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise TokenRejected("Token has no subject.")
        return VerifiedToken(subject=subject, scopes=_scopes(claims))


def _scopes(claims: dict[str, Any]) -> frozenset[str]:
    # RFC 9068 uses a space-separated `scope`; some servers emit an `scp` list.
    scope = claims.get("scope")
    if isinstance(scope, str):
        return frozenset(scope.split())
    scp = claims.get("scp")
    if isinstance(scp, list) and all(isinstance(item, str) for item in scp):
        return frozenset(scp)
    return frozenset()


def challenge(settings: OAuthSettings, scope: str, error: str | None = None) -> str:
    """The `WWW-Authenticate` value for a 401 or 403 (RFC 6750 section 3, RFC 9728 section 5.1)."""
    parts = []
    if error:
        parts.append(f'error="{error}"')
    parts.append(f'scope="{scope}"')
    parts.append(f'resource_metadata="{settings.metadata_url}"')
    return "Bearer " + ", ".join(parts)
