# password_manager/app/core/favicons.py
"""
Website logo (favicon) lookup with an on-disk cache.

Only the domain is ever sent over the network - never usernames, passwords or
notes. Each domain is fetched once; results (including "no logo found") are
cached under settings.FAVICON_DIR.
"""
import hashlib
import io
import ipaddress
import logging
import os
import re
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional
from urllib.parse import urlparse

from PIL import Image

from config import settings

LOGO_SIZE = 64                      # stored resolution (px)
MIN_SOURCE_SIZE = 24                # smaller icons are treated as "no logo"
MISS_RETRY_SECONDS = 7 * 24 * 3600  # retry domains without a logo after a week
TIMEOUT_SECONDS = 4
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PyPassManager"

# Service names that don't map to "<name>.com"
KNOWN_DOMAINS = {
    "gmail": "google.com", "google": "google.com", "youtube": "youtube.com",
    "outlook": "outlook.com", "hotmail": "outlook.com", "microsoft": "microsoft.com",
    "office": "office.com", "office 365": "office.com", "microsoft 365": "office.com",
    "teams": "teams.microsoft.com", "onedrive": "onedrive.live.com", "azure": "azure.microsoft.com",
    "aws": "aws.amazon.com", "aws console": "aws.amazon.com", "amazon web services": "aws.amazon.com",
    "icloud": "icloud.com", "apple": "apple.com", "apple id": "apple.com",
    "x": "x.com", "twitter": "x.com", "facebook": "facebook.com", "instagram": "instagram.com",
    "whatsapp": "whatsapp.com", "messenger": "messenger.com", "linkedin": "linkedin.com",
    "github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org",
    "stack overflow": "stackoverflow.com", "jira": "atlassian.com", "confluence": "atlassian.com",
    "bank of america": "bankofamerica.com", "chase": "chase.com", "wells fargo": "wellsfargo.com",
    "paypal": "paypal.com", "stripe": "stripe.com", "google drive": "drive.google.com",
    "google cloud": "cloud.google.com", "digitalocean": "digitalocean.com", "heroku": "heroku.com",
    "zoom": "zoom.us", "slack": "slack.com", "notion": "notion.so", "figma": "figma.com",
    "dropbox": "dropbox.com", "netflix": "netflix.com", "spotify": "spotify.com",
    "reddit": "reddit.com", "discord": "discord.com", "twitch": "twitch.tv",
    "steam": "steampowered.com", "epic games": "epicgames.com", "adobe": "adobe.com",
    "canva": "canva.com", "salesforce": "salesforce.com", "hubspot": "hubspot.com",
    "shopify": "shopify.com", "ebay": "ebay.com", "airbnb": "airbnb.com", "uber": "uber.com",
    "booking": "booking.com", "openai": "openai.com", "chatgpt": "chatgpt.com",
    "claude": "claude.ai", "anthropic": "anthropic.com", "yahoo": "yahoo.com",
    "proton": "proton.me", "protonmail": "proton.me", "telegram": "telegram.org",
}

_executor = ThreadPoolExecutor(max_workers=6, thread_name_prefix="favicon")
_memory_cache: dict = {}            # domain -> PIL.Image | None


def domain_from_url(url: str) -> str:
    """'https://www.github.com/login' -> 'github.com'."""
    if not url:
        return ""
    try:
        netloc = urlparse(url if "://" in url else f"https://{url}").hostname or ""
    except ValueError:
        return ""
    return netloc[4:] if netloc.startswith("www.") else netloc


def guess_domain(service: str, url: str = "") -> str:
    """Domain for an item: from its URL, a known service name, or '<name>.com'."""
    domain = domain_from_url(url)
    if domain:
        return domain
    name = (service or "").strip().lower()
    if not name:
        return ""
    if name in KNOWN_DOMAINS:
        return KNOWN_DOMAINS[name]
    if re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", name):    # service typed as a domain
        return name
    if re.fullmatch(r"[a-z0-9]+", name):                    # single word, e.g. "Amazon"
        return f"{name}.com"
    return ""


def _is_public_hostname(domain: str) -> bool:
    """False for IP addresses and local names (routers, intranet hosts) - never look those up."""
    if "." not in domain or domain.endswith((".local", ".lan", ".internal", ".localhost")):
        return False
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        return True


def _cache_paths(domain: str):
    key = hashlib.sha1(domain.encode("utf-8")).hexdigest()
    return os.path.join(settings.FAVICON_DIR, f"{key}.png"), os.path.join(settings.FAVICON_DIR, f"{key}.miss")


def _download(url: str) -> Optional[Image.Image]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        data = response.read(512 * 1024)
    image = Image.open(io.BytesIO(data))
    if image.format == "ICO" and image.info.get("sizes"):
        image.size = max(image.info["sizes"])    # multi-size .ico: use the largest
    image = image.convert("RGBA")
    if min(image.size) < MIN_SOURCE_SIZE:
        return None
    return image


def _fetch(domain: str) -> Optional[Image.Image]:
    # The site's own high-res icon first (only that site sees the request),
    # then Google's favicon service, which resolves most other sites.
    sources = (
        f"https://{domain}/apple-touch-icon.png",
        f"https://www.google.com/s2/favicons?domain={domain}&sz={LOGO_SIZE}",
        f"https://{domain}/favicon.ico",
    )
    for source in sources:
        try:
            image = _download(source)
            if image is not None:
                return image.resize((LOGO_SIZE, LOGO_SIZE), Image.LANCZOS)
        except Exception as e:
            logging.debug(f"Favicon source failed for {domain}: {type(e).__name__}")
    return None


def _load_or_fetch(domain: str) -> Optional[Image.Image]:
    png_path, miss_path = _cache_paths(domain)
    if os.path.exists(png_path):
        try:
            return Image.open(png_path).convert("RGBA")
        except Exception:
            os.remove(png_path)
    if os.path.exists(miss_path) and time.time() - os.path.getmtime(miss_path) < MISS_RETRY_SECONDS:
        return None

    image = _fetch(domain)
    try:
        os.makedirs(settings.FAVICON_DIR, exist_ok=True)
        if image is not None:
            image.save(png_path, "PNG")
            if os.path.exists(miss_path):
                os.remove(miss_path)
        else:
            open(miss_path, "w").close()
    except OSError as e:
        logging.warning(f"Could not write favicon cache: {e}")
    return image


def get_logo_async(domain: str, callback: Callable[[Optional[Image.Image]], None]):
    """Calls callback(image_or_None) from a worker thread. The caller must hop back
    to the Tk thread (e.g. widget.after) before touching widgets."""
    if not domain or not settings.FETCH_FAVICONS or not _is_public_hostname(domain):
        return
    if domain in _memory_cache:
        callback(_memory_cache[domain])
        return

    def work():
        image = _load_or_fetch(domain)
        _memory_cache[domain] = image
        callback(image)

    _executor.submit(work)
