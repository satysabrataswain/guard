from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

import requests


DEFAULT_TIMEOUT = 3.0
DEFAULT_MAX_REDIRECTS = 8
DEFAULT_MAX_RESPONSE_BYTES = 1_000_000


def _is_http_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False

    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.hostname)


def _is_private_or_local_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True

    return any(
        (
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
        )
    )


def _host_resolves_to_public_address(hostname: str, port: int | None) -> tuple[bool, list[str]]:
    """Resolve a hostname and reject private/local destinations."""

    if not hostname:
        return False, []

    try:
        infos = socket.getaddrinfo(
            hostname,
            port or 443,
            type=socket.SOCK_STREAM,
        )
    except (OSError, socket.gaierror):
        # A DNS failure is not a malicious verdict; it simply means the
        # redirect cannot safely be followed from this server.
        return False, []

    addresses = []

    for info in infos:
        sockaddr = info[4]
        address = sockaddr[0]

        if address not in addresses:
            addresses.append(address)

        if _is_private_or_local_ip(address):
            return False, addresses

    return bool(addresses), addresses


def _safe_redirect_target(base_url: str, location: str) -> str | None:
    """Resolve a Location header and validate its scheme/hostname."""

    if not location:
        return None

    target = urljoin(base_url, location.strip())

    if not _is_http_url(target):
        return None

    return target


def resolve_redirect_chain(
    url: str,
    *,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Inspect HTTP redirects without automatically following them.

    Returns a JSON-serializable dictionary suitable for API responses and
    JSONField storage.
    """

    original_url = str(url or "").strip()

    result: dict[str, Any] = {
        "enabled": True,
        "resolved": False,
        "original_url": original_url,
        "final_url": original_url,
        "redirect_chain": [],
        "redirect_count": 0,
        "status_codes": [],
        "shortener_detected": False,
        "error": "",
    }

    if not _is_http_url(original_url):
        result["enabled"] = False
        result["error"] = "Only HTTP/HTTPS URLs can be resolved."
        return result

    current_url = original_url
    chain = [original_url]
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "GUARD-Security-Scanner/1.0",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.1",
        }
    )

    try:
        for _ in range(max(0, int(max_redirects)) + 1):
            parsed = urlparse(current_url)
            hostname = parsed.hostname

            public, addresses = _host_resolves_to_public_address(
                hostname or "",
                parsed.port,
            )

            if not public:
                result["error"] = (
                    "Redirect target could not be safely resolved to a public IP address."
                )
                result["blocked_host"] = hostname or ""
                result["blocked_addresses"] = addresses
                break

            try:
                response = session.request(
                    "GET",
                    current_url,
                    allow_redirects=False,
                    timeout=timeout,
                    stream=True,
                )
            except requests.RequestException as exc:
                result["error"] = f"Redirect inspection request failed: {exc.__class__.__name__}."
                break

            try:
                result["status_codes"].append(response.status_code)
                location = response.headers.get("Location", "")
            finally:
                response.close()

            if not (300 <= response.status_code < 400) or not location:
                result["resolved"] = True
                result["final_url"] = current_url
                break

            next_url = _safe_redirect_target(current_url, location)

            if not next_url:
                result["error"] = "Redirect target is missing or uses an unsupported URL scheme."
                break

            if next_url in chain:
                result["error"] = "Redirect loop detected."
                chain.append(next_url)
                break

            chain.append(next_url)
            current_url = next_url
        else:
            result["error"] = "Maximum redirect limit reached."

    finally:
        session.close()

    result["redirect_chain"] = chain
    result["redirect_count"] = max(0, len(chain) - 1)
    result["final_url"] = current_url
    result["resolved"] = bool(result["resolved"] or result["redirect_count"] > 0)
    result["max_redirects"] = max_redirects
    result["timeout_seconds"] = timeout
    result["chain_length"] = len(chain)

    return result
