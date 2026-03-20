from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests


@dataclass
class HttpResult:
    url: str
    final_url: str
    status_code: int
    reason: str
    elapsed_ms: float
    headers: Dict[str, str]
    cookies: Dict[str, str]
    body_sample: str
    redirect_chain: List[str]


def fetch_target(url: str, timeout: int = 6) -> Optional[HttpResult]:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "WebFingerprint/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    )

    candidates = [url] if url.startswith(("http://", "https://")) else [f"https://{url}", f"http://{url}"]

    for candidate in candidates:
        try:
            start = time.perf_counter()
            response = session.get(candidate, timeout=timeout, allow_redirects=True)
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

            redirect_chain = [r.url for r in response.history] + [response.url]

            return HttpResult(
                url=candidate,
                final_url=response.url,
                status_code=response.status_code,
                reason=response.reason,
                elapsed_ms=elapsed_ms,
                headers=dict(response.headers),
                cookies={k: v for k, v in response.cookies.items()},
                body_sample=response.text[:50000],
                redirect_chain=redirect_chain,
            )
        except requests.RequestException:
            continue

    return None