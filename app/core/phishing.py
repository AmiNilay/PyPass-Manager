# password_manager/app/core/phishing.py
"""
Offline phishing / lookalike-domain guard.

Given an item's URL, flags domains that look like an impersonation of a
well-known brand or of another domain already saved in the user's vault:
IDN homographs (xn-- punycode), confusable characters (paypa1, rnicrosoft),
typosquatting (gooogle), brand-in-subdomain / combosquatting
(paypal.secure-login.com, paypal-verify.com) and suspicious TLD swaps
(paypal.co). Everything is computed locally - nothing is sent anywhere.
"""
import ipaddress
import logging
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, Optional

from app.core.favicons import KNOWN_DOMAINS, domain_from_url

logger = logging.getLogger(__name__)

HIGH = "high"
MEDIUM = "medium"
_SEVERITY_RANK = {HIGH: 2, MEDIUM: 1}

MIN_TYPO_LABEL = 5      # shorter trusted labels (ups, dhl, x) are too collision-prone
MIN_BRAND_TOKEN = 4     # minimum brand length for subdomain / combo matching

# Common multi-part public suffixes (small built-in subset of the PSL).
MULTI_PART_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "nhs.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "firm.in",
    "com.bd", "net.bd", "org.bd", "gov.bd", "edu.bd", "ac.bd",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.nz", "org.nz", "net.nz", "govt.nz",
    "co.za", "org.za", "gov.za",
    "com.mx", "org.mx", "gob.mx",
    "com.ar", "com.co", "com.pe", "com.ve", "com.ec", "com.uy",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.hk", "com.tw", "com.sg", "com.my", "com.ph", "com.vn", "com.pk", "com.np", "com.lk",
    "co.kr", "or.kr", "co.id", "co.th", "co.il", "co.ke", "com.ng", "com.eg", "com.sa",
    "com.tr", "gov.tr", "com.ua", "com.pl", "co.at", "or.at",
})

# ccTLDs on which the "many-country" brands below legitimately operate.
_LEGIT_COUNTRY_SUFFIXES = frozenset({
    "de", "fr", "it", "es", "nl", "be", "at", "ch", "se", "no", "dk", "fi", "pl", "ie",
    "pt", "cz", "gr", "hu", "ro", "ca", "in", "jp", "cn", "mx", "ru", "tr", "ae", "sg",
    "co.uk", "com.au", "co.in", "co.jp", "com.br", "com.mx", "com.tr", "co.nz", "co.za",
    "com.sg", "com.hk", "com.tw", "co.kr", "com.ar", "com.cn", "com.sa", "com.eg", "com.bd",
})
MULTI_COUNTRY_BRANDS = frozenset({
    "amazon", "google", "ebay", "apple", "microsoft", "paypal", "ikea", "booking",
    "samsung", "yahoo", "netflix", "dhl", "ups", "fedex",
})

# Commonly phished brand domains.
BRAND_DOMAINS = frozenset({
    # Payments / fintech / crypto
    "paypal.com", "paypal.me", "stripe.com", "venmo.com", "cash.app", "zellepay.com",
    "wise.com", "revolut.com", "skrill.com", "payoneer.com", "westernunion.com",
    "moneygram.com", "klarna.com", "afterpay.com", "squareup.com", "americanexpress.com",
    "visa.com", "mastercard.com", "discover.com", "coinbase.com", "binance.com",
    "kraken.com", "blockchain.com", "metamask.io", "crypto.com", "bitstamp.net",
    "kucoin.com", "okx.com", "bybit.com", "ledger.com", "trezor.io", "robinhood.com",
    # US banks
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "citibank.com",
    "capitalone.com", "usbank.com", "pnc.com", "tdbank.com", "truist.com",
    "schwab.com", "fidelity.com", "vanguard.com", "navyfederal.org", "usaa.com",
    "ally.com", "discoverbank.com", "regions.com", "key.com", "etrade.com",
    # EU / UK / global banks
    "hsbc.com", "hsbc.co.uk", "barclays.co.uk", "barclays.com", "lloydsbank.com",
    "natwest.com", "santander.com", "santander.co.uk", "halifax.co.uk", "nationwide.co.uk",
    "monzo.com", "starlingbank.com", "deutsche-bank.de", "commerzbank.de", "sparkasse.de",
    "ing.com", "ing.nl", "abnamro.nl", "rabobank.nl", "bnpparibas.com", "societegenerale.fr",
    "creditagricole.fr", "unicredit.it", "intesasanpaolo.com", "bbva.com", "caixabank.es",
    "ubs.com", "credit-suisse.com", "nordea.com", "danskebank.com", "n26.com",
    "rbc.com", "td.com", "scotiabank.com", "commbank.com.au", "westpac.com.au",
    "anz.com", "nab.com.au", "icicibank.com", "hdfcbank.com", "sbi.co.in", "axisbank.com",
    "standardchartered.com", "dbs.com.sg", "bkash.com", "dutchbanglabank.com",
    # Tech / identity / mail
    "microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com",
    "outlook.com", "hotmail.com", "onedrive.com", "sharepoint.com", "azure.com",
    "xbox.com", "skype.com", "google.com", "gmail.com", "youtube.com", "googleapis.com",
    "apple.com", "icloud.com", "me.com", "yahoo.com", "aol.com", "proton.me",
    "zoho.com", "adobe.com", "docusign.com", "docusign.net", "dropbox.com", "box.com",
    "wetransfer.com", "github.com", "gitlab.com", "bitbucket.org", "atlassian.com",
    "slack.com", "zoom.us", "salesforce.com", "okta.com", "godaddy.com", "namecheap.com",
    "cloudflare.com", "intuit.com", "quickbooks.com", "norton.com", "mcafee.com",
    "openai.com", "anthropic.com",
    # Social / messaging
    "facebook.com", "fb.com", "instagram.com", "whatsapp.com", "messenger.com",
    "meta.com", "linkedin.com", "twitter.com", "x.com", "tiktok.com", "snapchat.com",
    "telegram.org", "discord.com", "reddit.com", "pinterest.com", "signal.org",
    # Shopping / streaming / gaming / travel
    "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es",
    "amazon.ca", "amazon.in", "amazon.co.jp", "amazon.com.au", "ebay.com", "ebay.co.uk",
    "ebay.de", "aliexpress.com", "alibaba.com", "walmart.com", "target.com", "bestbuy.com",
    "etsy.com", "shopify.com", "ikea.com", "costco.com", "netflix.com", "spotify.com",
    "disneyplus.com", "hulu.com", "primevideo.com", "hbomax.com", "max.com", "twitch.tv",
    "steampowered.com", "steamcommunity.com", "epicgames.com", "roblox.com",
    "playstation.com", "nintendo.com", "ea.com", "booking.com", "airbnb.com",
    "expedia.com", "uber.com", "samsung.com",
    # Shipping / government
    "dhl.com", "dhl.de", "fedex.com", "ups.com", "usps.com", "royalmail.com",
    "irs.gov", "hmrc.gov.uk", "gov.uk", "ssa.gov",
})

# Visually confusable characters -> ASCII skeleton.
_CONFUSABLES = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ԁ": "d", "һ": "h", "ѕ": "s", "ӏ": "l", "к": "k", "м": "m",
    "т": "t", "в": "b", "н": "h", "ԛ": "q", "ԝ": "w",
    # Greek
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "τ": "t", "υ": "u",
    "ε": "e", "β": "b",
    # Digits / lookalike ASCII
    "0": "o", "1": "l", "5": "s", "3": "e", "4": "a", "7": "t", "8": "b",
}
_MULTI_CONFUSABLES = (("rn", "m"), ("vv", "w"), ("cl", "d"))


@dataclass
class Finding:
    kind: str
    severity: str
    message: str
    lookalike_of: Optional[str]


def split_domain(host: str) -> tuple[str, str, str]:
    """'login.paypal.co.uk' -> ('login', 'paypal', 'co.uk') - (subdomain, label, suffix)."""
    parts = [p for p in host.lower().strip(".").split(".") if p]
    if len(parts) < 2:
        return "", (parts[0] if parts else ""), ""
    suffix_len = 2 if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES else 1
    suffix = ".".join(parts[-suffix_len:])
    label = parts[-suffix_len - 1]
    sub = ".".join(parts[:-suffix_len - 1])
    return sub, label, suffix


def registrable_domain(host: str) -> str:
    """'login.paypal.co.uk' -> 'paypal.co.uk'."""
    _, label, suffix = split_domain(host)
    return f"{label}.{suffix}" if label and suffix else label


def skeleton(text: str) -> str:
    """Collapse confusable characters so lookalikes compare equal."""
    text = unicodedata.normalize("NFKC", text.lower())
    out = "".join(_CONFUSABLES.get(ch, ch) for ch in text)
    out = out.replace("i", "l")   # i / l / 1 are interchangeable at a glance
    for seq, repl in _MULTI_CONFUSABLES:
        out = out.replace(seq, repl)
    return out


def damerau_levenshtein(a: str, b: str, limit: int = 2) -> int:
    """Optimal-string-alignment distance; returns limit + 1 once it exceeds limit."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def _decode_host(host: str) -> str:
    """Decode punycode (xn--) labels to Unicode; undecodable labels are kept as-is."""
    labels = []
    for part in host.split("."):
        if part.startswith("xn--"):
            try:
                part = part[4:].encode("ascii").decode("punycode")
            except (UnicodeError, ValueError):
                logger.debug("Could not decode punycode label %r", part)
        labels.append(part)
    return ".".join(labels)


def _scripts(text: str) -> set[str]:
    scripts = set()
    for ch in text:
        if ch.isascii() or not ch.isalpha():
            continue
        try:
            scripts.add(unicodedata.name(ch).split(" ")[0])
        except ValueError:
            scripts.add("UNKNOWN")
    return scripts


class _TrustIndex:
    """Precomputed lookup tables over the trusted registrable domains."""

    def __init__(self, domains: Iterable[str]):
        self.domains: set[str] = set()
        self.by_label: dict[str, set[str]] = {}
        self.by_skeleton: dict[str, set[str]] = {}
        self.by_length: dict[int, list[str]] = {}
        for domain in domains:
            reg = registrable_domain(domain)
            _, label, _ = split_domain(reg)
            if not label or "." not in reg:
                continue
            self.domains.add(reg)
            if label not in self.by_label:
                self.by_length.setdefault(len(label), []).append(label)
                self.by_skeleton.setdefault(skeleton(label), set()).add(label)
            self.by_label.setdefault(label, set()).add(reg)

    def primary(self, label: str) -> str:
        """Representative domain for a trusted label (prefer .com)."""
        regs = self.by_label[label]
        return f"{label}.com" if f"{label}.com" in regs else sorted(regs)[0]


_BUILTIN_TRUSTED = BRAND_DOMAINS | {d for d in KNOWN_DOMAINS.values()}


@lru_cache(maxsize=8)
def _index_for(vault: frozenset) -> _TrustIndex:
    return _TrustIndex(_BUILTIN_TRUSTED | vault)


def _is_ignorable(host: str) -> bool:
    if not host or "." not in host or host.endswith((".local", ".lan", ".internal", ".localhost")):
        return True
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _is_legit(index: _TrustIndex, reg: str, label: str, suffix: str) -> bool:
    if reg in index.domains:
        return True
    return label in MULTI_COUNTRY_BRANDS and suffix in _LEGIT_COUNTRY_SUFFIXES


def analyze_url(url: str, vault_domains: Iterable[str] = ()) -> list[Finding]:
    """Return lookalike-domain findings for url, most severe first ([] if it looks fine).

    vault_domains are the user's *other* saved domains; they are treated as trusted
    (so they are both protected and whitelisted - don't include the URL's own domain).
    """
    host = (domain_from_url((url or "").strip()) or "").lower().rstrip(".")
    if _is_ignorable(host):
        return []

    vault = frozenset(r for r in (registrable_domain(domain_from_url(d) or d) for d in vault_domains if d) if "." in r)
    index = _index_for(vault)

    unicode_host = _decode_host(host)
    sub, label, suffix = split_domain(unicode_host)
    reg = f"{label}.{suffix}"
    if _is_legit(index, reg, label, suffix):
        return []

    findings: list[Finding] = []
    flagged: set[str] = set()   # trusted labels already reported

    def add(kind: str, severity: str, message: str, target: Optional[str]):
        findings.append(Finding(kind, severity, message, target))

    # 1. Punycode / IDN homograph
    if unicode_host != host or not host.isascii():
        scripts = _scripts(unicode_host)
        mixed = len(scripts | ({"LATIN"} if any(c.isascii() and c.isalpha() for c in unicode_host) else set())) > 1
        add("homograph", HIGH if mixed else MEDIUM,
            f"'{host}' is an internationalised domain that displays as '{unicode_host}'"
            + (" and mixes alphabets (" + ", ".join(sorted(scripts | {"LATIN"})).title() + ")" if mixed else ""),
            None)

    # 2. Confusable characters
    for trusted in index.by_skeleton.get(skeleton(label), ()):
        if trusted != label:
            target = index.primary(trusted)
            add("confusable", HIGH, f"{reg} looks like {target} (lookalike characters)", target)
            flagged.add(trusted)
    if findings and findings[0].kind == "homograph" and flagged:
        findings[0].lookalike_of = index.primary(next(iter(flagged)))
        findings[0].severity = HIGH

    # 3. Typosquatting
    ascii_label = skeleton(label) if not label.isascii() else label
    for length in range(len(ascii_label) - 2, len(ascii_label) + 3):
        for trusted in index.by_length.get(length, ()):
            if trusted == ascii_label or trusted in flagged or len(trusted) < MIN_TYPO_LABEL:
                continue
            limit = 2 if len(trusted) >= 9 else 1
            dist = damerau_levenshtein(ascii_label, trusted, limit)
            if dist <= limit:
                target = index.primary(trusted)
                add("typosquat", HIGH if dist == 1 else MEDIUM,
                    f"{reg} is a near-misspelling of {target}", target)
                flagged.add(trusted)

    # 4. Brand in subdomain / combosquatting
    for token in {t for part in sub.split(".") for t in part.split("-") if t}:
        if len(token) >= MIN_BRAND_TOKEN and token in index.by_label and token not in flagged:
            target = index.primary(token)
            add("brand_in_subdomain", HIGH,
                f"'{token}' appears in the subdomain, but the real site is {reg}, not {target}", target)
            flagged.add(token)
    if "-" in label:
        for token in label.split("-"):
            if len(token) >= MIN_BRAND_TOKEN and token in index.by_label and token not in flagged:
                target = index.primary(token)
                add("combosquat", MEDIUM, f"{reg} combines '{token}' with extra words - not {target}", target)
                flagged.add(token)

    # 5. TLD swap
    if label in index.by_label and label not in flagged:
        target = index.primary(label)
        add("tld_swap", MEDIUM, f"{reg} uses an unusual ending for {target}", target)

    findings.sort(key=lambda f: -_SEVERITY_RANK.get(f.severity, 0))
    if findings:
        logger.debug("Lookalike findings for %s: %s", host, [f.kind for f in findings])
    return findings


def worst(findings: Iterable[Finding]) -> Optional[Finding]:
    """The most severe finding, or None."""
    return max(findings, key=lambda f: _SEVERITY_RANK.get(f.severity, 0), default=None)
