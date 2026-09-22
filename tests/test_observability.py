"""Authentication tests for Homework 2's session endpoints.

Both tests call the FastAPI route functions directly (no TestClient, no
running server) and never touch Langfuse, Docker, or a model provider key,
per the Part D instructions. They rely on the same session-scoped `world`
fixture used by tests/test_hw_holes.py.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from server import app as server_app


@pytest.fixture(autouse=True)
def _clear_sessions() -> None:
    """Each test starts with an empty in-memory session store."""
    server_app._SESSIONS.clear()
    yield
    server_app._SESSIONS.clear()


def test_create_session_rejects_role_mismatch(world: dict) -> None:
    """A claimed role that does not match the stored database role is a 403.

    User 1 is a shopper in the seeded world (see SHOPPER_1 in
    test_hw_holes.py). Claiming "merchant" for that same user id must be
    rejected before any session or token is created.
    """
    with pytest.raises(HTTPException) as excinfo:
        server_app.create_session(server_app.SessionCreate(user_id=1, role="merchant"))
    assert excinfo.value.status_code == 403
    assert server_app._SESSIONS == {}


def test_token_from_one_session_cannot_authorize_another(world: dict) -> None:
    """A valid, correctly-signed token is only good for the session it names.

    Creating two real sessions for two real users, then presenting session
    A's token against session B's URL, must be rejected even though the
    token's signature and identity are both genuine.
    """
    session_a = server_app.create_session(server_app.SessionCreate(user_id=1, role="shopper"))
    session_b = server_app.create_session(
        server_app.SessionCreate(user_id=9001, role="merchant")
    )

    token_for_a = session_a["token"]
    session_id_b = session_b["session_id"]

    with pytest.raises(HTTPException) as excinfo:
        server_app._authorize(session_id_b, f"Bearer {token_for_a}")
    assert excinfo.value.status_code == 403

    # Sanity check: each token still authorizes its own session correctly.
    ctx_a = server_app._authorize(session_a["session_id"], f"Bearer {token_for_a}")
    assert ctx_a.user_id == 1
    assert ctx_a.role == "shopper"