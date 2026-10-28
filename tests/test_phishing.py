"""Tests for the offline lookalike-domain guard."""
import time

import pytest

from app.core.phishing import Finding, analyze_url, registrable_domain, worst


@pytest.mark.parametrize("url", [
    "https://paypal.com", "https://www.paypal.com/signin", "accounts.google.com",
    "https://www.amazon.co.uk", "amazon.de", "https://github.com/login",
    "https://login.microsoftonline.com", "myblog.dev", "https://google.co.in",
    "ebay.de", "https://www.netflix.com", "steamcommunity.com", "web.whatsapp.com",
    "example.org", "https://news.ycombinator.com", "chase.com", "icloud.com",
])
def test_legit_domains_have_no_findings(url):
    assert analyze_url(url) == []


@pytest.mark.parametrize("url,kind,severity", [
    ("paypa1.com", "confusable", "high"),
    ("rnicrosoft.com", "confusable", "high"),
    ("gooogle.com", "typosquat", "high"),
    ("arnazon.com", "confusable", "high"),
    ("faceb00k.com", "confusable", "high"),
    ("https://xn--pypal-4ve.com/login", "homograph", "high"),
    ("https://paypal.secure-login.com", "brand_in_subdomain", "high"),
    ("paypal-verify.com", "combosquat", "medium"),
    ("netflix-billing.net", "combosquat", "medium"),
    ("microsoft-support-account.net", "combosquat", "medium"),
    ("paypal.co", "tld_swap", "medium"),
])
def test_attacks_are_flagged(url, kind, severity):
    findings = analyze_url(url)
    assert any(f.kind == kind for f in findings), findings
    assert worst(findings).severity == severity


def test_homograph_points_at_brand():
    top = worst(analyze_url("xn--pypal-4ve.com"))
    assert top.lookalike_of == "paypal.com"
    assert "pаypal" in top.message


def test_vault_domain_protects_and_is_trusted():
    vault = ["https://mybank.com.bd/login"]
    assert analyze_url("mybank.com.bd", vault) == []
    findings = analyze_url("https://mybenk.com.bd", vault)
    assert worst(findings).lookalike_of == "mybank.com.bd"
    assert analyze_url("mybenk.com.bd") == []


@pytest.mark.parametrize("url", ["", None, "http://192.168.1.1", "localhost:8080", "[::1]", "router"])
def test_ignorable_urls(url):
    assert analyze_url(url) == []


def test_registrable_domain():
    assert registrable_domain("login.paypal.co.uk") == "paypal.co.uk"
    assert registrable_domain("a.b.example.com") == "example.com"


def test_worst():
    assert worst([]) is None
    m, h = Finding("x", "medium", "", None), Finding("y", "high", "", None)
    assert worst([m, h]) is h


def test_fast_enough():
    vault = [f"site{i}-example.com" for i in range(500)]
    start = time.perf_counter()
    for i in range(500):
        analyze_url(f"https://shop{i}.example.net", vault)
    assert time.perf_counter() - start < 5
