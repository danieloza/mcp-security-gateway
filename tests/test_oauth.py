"""OAuth resource-server mode: tokens are signed with keys generated here and resolved
from a fixed JWKS, so no authorization server or network is needed."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from mcp_security_gateway.main import create_app
from mcp_security_gateway.oauth import (
    OAuthConfigError,
    SigningKeysUnavailable,
    TokenRejected,
    TokenVerifier,
    load_oauth_settings,
    static_key_source,
)
from mcp_security_gateway.repository import SQLiteRepository
from mcp_security_gateway.state import InMemoryRateLimitStore

RESOURCE = "http://testserver/mcp"
ISSUER = "https://issuer.test/realms/gateway"
METADATA_PATH = "/.well-known/oauth-protected-resource/mcp"
METADATA_URL = f"http://testserver{METADATA_PATH}"
KID = "gateway-test-key"

SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWKS = {"keys": [{**RSAAlgorithm.to_jwk(SIGNING_KEY.public_key(), as_dict=True), "kid": KID, "use": "sig", "alg": "RS256"}]}


@pytest.fixture
def oauth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MSG_AUTH_MODE", "oauth")
    monkeypatch.setenv("MSG_OAUTH_RESOURCE", RESOURCE)
    monkeypatch.setenv("MSG_OAUTH_ISSUER", ISSUER)
    monkeypatch.setenv("MSG_OAUTH_JWKS_URL", "https://issuer.test/realms/gateway/certs")
    monkeypatch.setenv("MSG_OAUTH_SUBJECTS", "sub-ops=usr_ops,sub-security=usr_security,sub-ghost=usr_missing")


def make_oauth_client(tmp_path: Path, key_source: Any = None) -> TestClient:
    settings = load_oauth_settings()
    verifier = TokenVerifier(settings, key_source or static_key_source(JWKS))
    repo = SQLiteRepository(f"sqlite:///{tmp_path / 'gateway.db'}")
    return TestClient(create_app(repo, InMemoryRateLimitStore(), verifier))


def claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    base: dict[str, Any] = {
        "iss": ISSUER,
        "aud": RESOURCE,
        "sub": "sub-ops",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "scope": "mcp:tools gateway:console",
    }
    for key, value in overrides.items():
        if value is None:
            base.pop(key, None)
        else:
            base[key] = value
    return base


def token(key: Any = SIGNING_KEY, kid: str = KID, **overrides: Any) -> str:
    return jwt.encode(claims(**overrides), key, algorithm="RS256", headers={"kid": kid})


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def handmade(header: dict[str, Any], body: dict[str, Any], secret: bytes | None) -> str:
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(body).encode())}"
    signature = _b64(hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()) if secret else ""
    return f"{signing_input}.{signature}"


def bearer(value: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {value}"}


def mcp(client: TestClient, headers: dict[str, str], method: str, params: dict[str, Any] | None = None) -> Any:
    return client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})


def challenge_params(response: Any) -> dict[str, str]:
    value = response.headers["www-authenticate"]
    assert value.startswith("Bearer ")
    return dict(part.strip().split("=", 1) for part in value.removeprefix("Bearer ").split(","))


def test_metadata_document_describes_the_mcp_resource(oauth_env: None, tmp_path: Path) -> None:
    client = make_oauth_client(tmp_path)
    response = client.get(METADATA_PATH)
    assert response.status_code == 200
    document = response.json()
    assert document["resource"] == RESOURCE
    assert document["authorization_servers"] == [ISSUER]
    assert document["scopes_supported"] == ["mcp:tools", "gateway:console"]
    assert document["bearer_methods_supported"] == ["header"]
    # Only the path-inserted URI: a root document would have to describe the origin.
    assert client.get("/.well-known/oauth-protected-resource").status_code == 404


def test_static_mode_publishes_no_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MSG_AUTH_MODE", raising=False)
    client = TestClient(create_app(SQLiteRepository(f"sqlite:///{tmp_path / 'gateway.db'}"), InMemoryRateLimitStore()))
    assert client.get(METADATA_PATH).status_code == 404
    assert client.get("/health").json()["auth_mode"] == "static"


def test_missing_token_gets_a_discovery_challenge(oauth_env: None, tmp_path: Path) -> None:
    client = make_oauth_client(tmp_path)
    response = mcp(client, {}, "tools/list")
    assert response.status_code == 401
    params = challenge_params(response)
    assert params == {"scope": '"mcp:tools"', "resource_metadata": f'"{METADATA_URL}"'}
    console = client.get("/me")
    assert console.status_code == 401
    assert challenge_params(console)["scope"] == '"gateway:console"'


INVALID_TOKENS = {
    "wrong audience": lambda: token(aud="http://testserver/other-mcp"),
    "no audience": lambda: token(aud=None),
    "expired": lambda: token(exp=int(time.time()) - 120, iat=int(time.time()) - 600, nbf=int(time.time()) - 600),
    "not yet valid": lambda: token(nbf=int(time.time()) + 600),
    "wrong issuer": lambda: token(iss="https://evil.test/realms/gateway"),
    "bad signature": lambda: token(key=OTHER_KEY),
    "unknown key id": lambda: token(kid="rotated-away"),
    "no subject": lambda: token(sub=None),
    "alg none": lambda: handmade({"alg": "none", "typ": "JWT", "kid": KID}, claims(), None),
    "HS256 with the public key as secret": lambda: handmade(
        {"alg": "HS256", "typ": "JWT", "kid": KID},
        claims(),
        SIGNING_KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
    ),
    "static demo key": lambda: "msg-ops-demo",
    "not a token": lambda: "a.b.c",
}


@pytest.mark.parametrize("case", list(INVALID_TOKENS))
def test_invalid_tokens_are_refused_with_401(oauth_env: None, tmp_path: Path, case: str) -> None:
    client = make_oauth_client(tmp_path)
    value = INVALID_TOKENS[case]()
    response = mcp(client, bearer(value), "tools/list")
    assert response.status_code == 401
    params = challenge_params(response)
    assert params["error"] == '"invalid_token"'
    assert params["resource_metadata"] == f'"{METADATA_URL}"'
    # Nothing from the token comes back in the error.
    assert value not in response.text
    assert "sub-ops" not in response.text


@pytest.mark.parametrize("case", ["alg none", "HS256 with the public key as secret"])
def test_disallowed_algorithms_are_refused_before_any_key_lookup(oauth_env: None, case: str) -> None:
    # The allowlist check comes before the key source, so a forged header never
    # makes the gateway fetch keys from the authorization server.
    lookups: list[str] = []

    def recording(value: str) -> Any:
        lookups.append(value)
        return static_key_source(JWKS)(value)

    verifier = TokenVerifier(load_oauth_settings(), recording)
    with pytest.raises(TokenRejected):
        verifier.verify(INVALID_TOKENS[case]())
    assert lookups == []


def test_x_api_key_is_not_a_credential_in_oauth_mode(oauth_env: None, tmp_path: Path) -> None:
    client = make_oauth_client(tmp_path)
    alone = mcp(client, {"X-API-Key": "msg-ops-demo"}, "tools/list")
    with_token = mcp(client, {**bearer(token()), "X-API-Key": "msg-ops-demo"}, "tools/list")
    assert alone.status_code == 401
    assert with_token.status_code == 401


def test_missing_scope_gets_403_insufficient_scope(oauth_env: None, tmp_path: Path) -> None:
    client = make_oauth_client(tmp_path)
    console_only = mcp(client, bearer(token(scope="gateway:console")), "tools/list")
    mcp_only = client.get("/me", headers=bearer(token(scope="mcp:tools")))
    for response, scope in ((console_only, "mcp:tools"), (mcp_only, "gateway:console")):
        assert response.status_code == 403
        params = challenge_params(response)
        assert params["error"] == '"insufficient_scope"'
        assert params["scope"] == f'"{scope}"'
        assert params["resource_metadata"] == f'"{METADATA_URL}"'


def test_scp_list_is_read_as_scopes(oauth_env: None, tmp_path: Path) -> None:
    client = make_oauth_client(tmp_path)
    response = mcp(client, bearer(token(scope=None, scp=["mcp:tools"])), "tools/list")
    assert response.status_code == 200


@pytest.mark.parametrize("subject", ["sub-stranger", "sub-ghost"])
def test_unknown_subject_is_refused_not_created(oauth_env: None, tmp_path: Path, subject: str) -> None:
    # sub-stranger is not mapped; sub-ghost maps to a user id that does not exist.
    client = make_oauth_client(tmp_path)
    response = mcp(client, bearer(token(sub=subject)), "tools/list")
    assert response.status_code == 403
    assert "insufficient_scope" not in response.headers.get("www-authenticate", "")


def test_valid_token_reaches_a_governed_tool_call(oauth_env: None, tmp_path: Path) -> None:
    client = make_oauth_client(tmp_path)
    headers = bearer(token())
    initialize = mcp(client, headers, "initialize", {"protocolVersion": "2025-11-25"})
    tools = mcp(client, headers, "tools/list")
    call = mcp(client, headers, "tools/call", {"name": "kb.search", "arguments": {"query": "manifest quarantine"}})
    me = client.get("/me", headers=headers)
    assert initialize.status_code == 200
    assert [tool["name"] for tool in tools.json()["result"]["tools"]] == ["kb.search", "ops.restart_service", "repo.write_file"]
    assert call.json()["result"]["structuredContent"]["status"] == "executed"
    assert me.json()["id"] == "usr_ops"


def test_maker_checker_separation_holds_with_oauth_identities(oauth_env: None, tmp_path: Path) -> None:
    client = make_oauth_client(tmp_path)
    maker = bearer(token(sub="sub-ops"))
    checker = bearer(token(sub="sub-security"))
    created = client.post(
        "/requests",
        headers=maker,
        json={
            "mcp_server_id": "mcp_github",
            "tool_name": "repo.write_file",
            "requested_scope": "repo:write",
            "justification": "Stage a controlled documentation change in the sandbox.",
            "estimated_tokens": 600,
            "arguments": {"path": "docs/review.md", "content": "approved evidence"},
        },
    )
    assert created.status_code == 201
    approval_id = client.get("/approvals", headers=maker).json()[0]["id"]
    self_approval = client.post(f"/approvals/{approval_id}/decision", headers=maker, json={"decision": "approved"})
    checked = client.post(f"/approvals/{approval_id}/decision", headers=checker, json={"decision": "approved"})
    assert self_approval.status_code == 403
    assert checked.status_code == 200


def test_unavailable_signing_keys_are_503_not_401(oauth_env: None, tmp_path: Path) -> None:
    def unavailable(_token: str) -> Any:
        raise SigningKeysUnavailable("down")

    client = make_oauth_client(tmp_path, key_source=unavailable)
    response = mcp(client, bearer(token()), "tools/list")
    assert response.status_code == 503


def test_production_refuses_static_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MSG_ENVIRONMENT", "production")
    monkeypatch.delenv("MSG_AUTH_MODE", raising=False)
    with pytest.raises(RuntimeError, match="MSG_AUTH_MODE=oauth"):
        create_app(SQLiteRepository(f"sqlite:///{tmp_path / 'gateway.db'}"), InMemoryRateLimitStore())


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("MSG_OAUTH_ALGORITHMS", "RS256,HS256", "asymmetric"),
        ("MSG_OAUTH_ALGORITHMS", "none", "asymmetric"),
        ("MSG_OAUTH_SUBJECTS", "sub-ops", "subject=user_id"),
        ("MSG_OAUTH_RESOURCE", "mcp", "absolute"),
    ],
)
def test_unsafe_settings_refuse_to_start(oauth_env: None, monkeypatch: pytest.MonkeyPatch, name: str, value: str, message: str) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(OAuthConfigError, match=message):
        load_oauth_settings()


def test_resource_setting_is_canonical_without_trailing_slash(oauth_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MSG_OAUTH_RESOURCE", RESOURCE + "/")
    assert load_oauth_settings().resource == RESOURCE
