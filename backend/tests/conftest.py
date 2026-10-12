"""Shared pytest fixtures — keep the suite hermetic and free to run."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


@pytest.fixture(autouse=True)
def _no_real_openai(monkeypatch):
    """Never call the real OpenAI API from tests.

    A developer's backend/.env usually holds a real OPENAI_API_KEY; without
    this, every mode="full" test made a paid GPT call (~4-5s each). With the
    key blanked, the AI layer uses its deterministic local fallback.
    """
    monkeypatch.setattr("app.ai.service.settings.openai_api_key", "")


@pytest.fixture(autouse=True)
def _hermetic_mx_lookup():
    """Full-scan tests must not do real MX lookups.

    Default: every host "has MX" (email auth graded everywhere, i.e. the
    pre-existing behaviour). Tests about email applicability override this.
    """
    with patch("app.api.routes.has_mx", AsyncMock(return_value=True)) as m:
        yield m


@pytest.fixture(autouse=True)
def _hermetic_private_ip_check():
    """Default: every host resolves to public IPs only (no real DNS in tests)."""
    with patch("app.api.routes.non_public_ips", AsyncMock(return_value=[])) as m:
        yield m
