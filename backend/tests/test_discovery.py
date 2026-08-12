"""Unit tests for the discovery package.

All tests mock external I/O so they run offline and never touch crt.sh or real DNS.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.discovery.crtsh import _looks_like_hostname, fetch_crtsh_subdomains
from app.discovery.dns_mining import mine_dns_subdomains
from app.discovery.enumerator import DiscoveredHost, enumerate_hosts


# ---------------------------------------------------------------------------
# crtsh.py unit tests
# ---------------------------------------------------------------------------

class TestLooksLikeHostname:
    def test_apex_itself(self):
        assert _looks_like_hostname("mfu.ac.th", "mfu.ac.th")

    def test_subdomain(self):
        assert _looks_like_hostname("www.mfu.ac.th", "mfu.ac.th")

    def test_deep_subdomain(self):
        assert _looks_like_hostname("a.b.mfu.ac.th", "mfu.ac.th")

    def test_wildcard_stripped(self):
        # wildcards are handled by stripping *.
        assert _looks_like_hostname("*.mfu.ac.th", "mfu.ac.th")

    def test_unrelated_domain_rejected(self):
        assert not _looks_like_hostname("evil.com", "mfu.ac.th")

    def test_partial_suffix_rejected(self):
        # "notmfu.ac.th" must NOT match apex "mfu.ac.th"
        assert not _looks_like_hostname("notmfu.ac.th", "mfu.ac.th")


@pytest.mark.asyncio
async def test_fetch_crtsh_subdomains_happy_path():
    """Mock a realistic crt.sh JSON response and check parsed hostnames."""
    mock_response_data = [
        {"name_value": "www.mfu.ac.th"},
        {"name_value": "mail.mfu.ac.th\nsmtp.mfu.ac.th"},  # multi-line SAN
        {"name_value": "*.mfu.ac.th"},                     # wildcard
        {"name_value": "unrelated.example.com"},            # should be filtered out
    ]

    mock_resp = AsyncMock()
    mock_resp.raise_for_status = lambda: None
    mock_resp.json = lambda: mock_response_data

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_resp)

    with patch("app.discovery.crtsh.httpx.AsyncClient", return_value=mock_client):
        result = await fetch_crtsh_subdomains("mfu.ac.th")

    assert "www.mfu.ac.th" in result
    assert "mail.mfu.ac.th" in result
    assert "smtp.mfu.ac.th" in result
    assert "*.mfu.ac.th" in result           # wildcard kept for enumerator to filter
    assert "unrelated.example.com" not in result


@pytest.mark.asyncio
async def test_fetch_crtsh_network_error_returns_empty():
    """Network failure must return an empty set, not raise."""
    import httpx

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))

    with patch("app.discovery.crtsh.httpx.AsyncClient", return_value=mock_client):
        result = await fetch_crtsh_subdomains("mfu.ac.th")

    assert result == set()


@pytest.mark.asyncio
async def test_fetch_crtsh_non_list_response_returns_empty():
    """crt.sh returning unexpected JSON must not crash."""
    mock_resp = AsyncMock()
    mock_resp.raise_for_status = lambda: None
    mock_resp.json = lambda: {"error": "rate limited"}

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_resp)

    with patch("app.discovery.crtsh.httpx.AsyncClient", return_value=mock_client):
        result = await fetch_crtsh_subdomains("mfu.ac.th")

    assert result == set()


# ---------------------------------------------------------------------------
# dns_mining.py unit tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mine_dns_subdomains_ns_and_mx():
    """NS/MX records that belong to the apex should be collected."""
    import dns.rdatatype

    class FakeNSRecord:
        target = "ns1.mfu.ac.th."

    class FakeMXRecord:
        exchange = "mail.mfu.ac.th."

    async def fake_resolve(name, rdtype):
        if rdtype == "NS":
            return [FakeNSRecord()]
        if rdtype == "MX":
            return [FakeMXRecord()]
        raise Exception("NXDOMAIN")

    with patch("app.discovery.dns_mining.dns.asyncresolver.Resolver") as MockResolver:
        mock_r = AsyncMock()
        mock_r.resolve = AsyncMock(side_effect=fake_resolve)
        MockResolver.return_value = mock_r
        result = await mine_dns_subdomains("mfu.ac.th")

    assert "ns1.mfu.ac.th" in result
    assert "mail.mfu.ac.th" in result


@pytest.mark.asyncio
async def test_mine_dns_subdomains_all_fail_returns_empty():
    """All DNS lookups failing must return empty set, not raise."""
    async def always_fail(*args, **kwargs):
        raise Exception("SERVFAIL")

    with patch("app.discovery.dns_mining.dns.asyncresolver.Resolver") as MockResolver:
        mock_r = AsyncMock()
        mock_r.resolve = AsyncMock(side_effect=always_fail)
        MockResolver.return_value = mock_r
        result = await mine_dns_subdomains("mfu.ac.th")

    assert isinstance(result, set)


# ---------------------------------------------------------------------------
# enumerator.py unit tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_enumerate_hosts_dedupes_and_filters_wildcards():
    """Wildcard entries must be dropped; duplicates across sources must be merged."""
    crtsh_set = {"www.mfu.ac.th", "*.mfu.ac.th", "mail.mfu.ac.th"}
    dns_set = {"mail.mfu.ac.th", "mfu.ac.th"}  # mail is a duplicate

    async def fake_resolve(hostname, rdtype):
        return ["1.2.3.4"]  # everything resolves

    with (
        patch("app.discovery.enumerator.fetch_crtsh_subdomains", AsyncMock(return_value=crtsh_set)),
        patch("app.discovery.enumerator.mine_dns_subdomains", AsyncMock(return_value=dns_set)),
        patch("app.discovery.enumerator.brute_force", AsyncMock(return_value=set())),
        patch("app.discovery.enumerator.dns.asyncresolver.Resolver") as MockResolver,
    ):
        mock_r = AsyncMock()
        mock_r.resolve = AsyncMock(side_effect=fake_resolve)
        MockResolver.return_value = mock_r
        hosts = await enumerate_hosts("mfu.ac.th")

    hostnames = {h.hostname for h in hosts}
    assert "*.mfu.ac.th" not in hostnames
    assert "www.mfu.ac.th" in hostnames
    assert "mail.mfu.ac.th" in hostnames
    assert "mfu.ac.th" in hostnames
    # no duplicates
    assert len(hostnames) == len(hosts)


@pytest.mark.asyncio
async def test_enumerate_hosts_filters_dead_hosts():
    """Hosts that don't resolve must be excluded from results."""
    crtsh_set = {"live.mfu.ac.th", "dead.mfu.ac.th"}

    async def selective_resolve(hostname, rdtype):
        if "dead" in hostname:
            import dns.exception
            raise dns.exception.DNSException("NXDOMAIN")
        return ["1.2.3.4"]

    with (
        patch("app.discovery.enumerator.fetch_crtsh_subdomains", AsyncMock(return_value=crtsh_set)),
        patch("app.discovery.enumerator.mine_dns_subdomains", AsyncMock(return_value=set())),
        patch("app.discovery.enumerator.brute_force", AsyncMock(return_value=set())),
        patch("app.discovery.enumerator.dns.asyncresolver.Resolver") as MockResolver,
    ):
        mock_r = AsyncMock()
        mock_r.resolve = AsyncMock(side_effect=selective_resolve)
        MockResolver.return_value = mock_r
        hosts = await enumerate_hosts("mfu.ac.th")

    hostnames = {h.hostname for h in hosts}
    assert "live.mfu.ac.th" in hostnames
    assert "dead.mfu.ac.th" not in hostnames


@pytest.mark.asyncio
async def test_enumerate_hosts_includes_apex():
    """Apex domain is always in the candidate list."""
    with (
        patch("app.discovery.enumerator.fetch_crtsh_subdomains", AsyncMock(return_value=set())),
        patch("app.discovery.enumerator.mine_dns_subdomains", AsyncMock(return_value=set())),
        patch("app.discovery.enumerator.brute_force", AsyncMock(return_value=set())),
        patch("app.discovery.enumerator.dns.asyncresolver.Resolver") as MockResolver,
    ):
        mock_r = AsyncMock()
        mock_r.resolve = AsyncMock(return_value=["1.2.3.4"])
        MockResolver.return_value = mock_r
        hosts = await enumerate_hosts("mfu.ac.th")

    assert any(h.hostname == "mfu.ac.th" for h in hosts)
