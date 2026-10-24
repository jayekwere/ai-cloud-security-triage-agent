"""Small HTTPS transport: fixed hosts, no redirects, bounded bytes, finite retries."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirects are forbidden")


def request_json(
    url: str,
    *,
    allowed_host: str,
    payload: dict | None = None,
    headers: dict[str, str] | None = None,
    retries: int = 0,
) -> Any:
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or parts.hostname != allowed_host
        or parts.username
        or parts.password
        or parts.port not in {None, 443}
        or parts.fragment
    ):
        raise ValueError("destination must be the configured HTTPS host on port 443")
    body = None if payload is None else json.dumps(payload, allow_nan=False).encode()
    request = urllib.request.Request(  # noqa: S310 - HTTPS/host checked immediately above
        url,
        data=body,
        headers={
            "User-Agent": "cloudtriage-portfolio/0.1",
            "Content-Type": "application/json",
            **(headers or {}),
        },
    )
    opener = urllib.request.build_opener(NoRedirect())
    # Retry only safe reads; never retry a potentially committed remote mutation.
    attempts = 1 + (min(retries, 2) if payload is None else 0)
    for attempt in range(attempts):
        try:
            # URL is constrained above; urllib uses the default TLS certificate verification.
            with opener.open(request, timeout=20) as response:  # nosec B310
                raw = response.read(8_000_001)
            if len(raw) > 8_000_000:
                raise ValueError("HTTP response exceeds 8 MB limit")
            return json.loads(raw)
        except (urllib.error.URLError, TimeoutError):
            if attempt + 1 == attempts:
                raise RuntimeError(
                    "remote request failed; inspect provider status, no secrets logged"
                ) from None
            time.sleep(0.25 * 2**attempt)
    raise RuntimeError("unreachable transport state")
