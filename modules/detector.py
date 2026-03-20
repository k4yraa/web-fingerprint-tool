from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class FingerprintResult:
    server: str
    powered_by: str
    technologies: List[str]
    security_headers: Dict[str, str]
    cookie_names: List[str]
    confidence: str


def _contains(text: str, patterns: List[str]) -> bool:
    lowered = text.lower()
    return any(p.lower() in lowered for p in patterns)


def detect_technologies(headers: Dict[str, str], body: str, cookies: Dict[str, str]) -> List[str]:
    tech: List[str] = []

    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    all_headers = " ".join(f"{k}: {v}" for k, v in headers.items())
    cookie_names = " ".join(cookies.keys())

    if _contains(server, ["cloudflare"]) or _contains(all_headers, ["cf-ray", "__cf_bm", "cf-cache-status"]):
        tech.append("Cloudflare")

    if _contains(server, ["nginx"]):
        tech.append("Nginx")

    if _contains(server, ["apache"]):
        tech.append("Apache")

    if _contains(powered, ["express"]):
        tech.append("Express")

    if _contains(powered, ["php"]):
        tech.append("PHP")

    if _contains(powered, ["asp.net"]):
        tech.append("ASP.NET")

    if _contains(body, ["/wp-content/", "wp-includes", "wordpress"]):
        tech.append("WordPress")

    if _contains(body, ["__next", "_next/static", "next.js"]):
        tech.append("Next.js")

    if _contains(body, ["react", "__react", "data-reactroot"]):
        tech.append("React")

    if _contains(body, ["vue", "__vue", "data-v-"]):
        tech.append("Vue.js")

    if _contains(body, ["angular", "ng-version"]):
        tech.append("Angular")

    if _contains(cookie_names, ["phpsessid"]):
        tech.append("PHP Session")

    if _contains(cookie_names, ["wordpress_", "wordpress_logged_in", "wp-settings-"]):
        tech.append("WordPress Auth")

    if _contains(cookie_names, ["laravel_session"]):
        tech.append("Laravel")

    # Tekrarlı girişleri temizle
    deduped: List[str] = []
    for item in tech:
        if item not in deduped:
            deduped.append(item)

    return deduped


def analyze_security_headers(headers: Dict[str, str]) -> Dict[str, str]:
    checks = {
        "Strict-Transport-Security": "Missing",
        "Content-Security-Policy": "Missing",
        "X-Frame-Options": "Missing",
        "X-Content-Type-Options": "Missing",
        "Referrer-Policy": "Missing",
        "Permissions-Policy": "Missing",
    }

    for key in list(checks.keys()):
        if headers.get(key):
            checks[key] = "Present"

    return checks


def score_confidence(technologies: List[str], headers: Dict[str, str], cookies: Dict[str, str]) -> str:
    score = 0

    if technologies:
        score += min(len(technologies), 4)

    if headers.get("Server"):
        score += 1

    if headers.get("X-Powered-By"):
        score += 1

    if cookies:
        score += 1

    if score >= 5:
        return "High"
    if score >= 3:
        return "Medium"
    return "Low"


def fingerprint(headers: Dict[str, str], body: str, cookies: Dict[str, str]) -> FingerprintResult:
    technologies = detect_technologies(headers, body, cookies)
    security_headers = analyze_security_headers(headers)
    confidence = score_confidence(technologies, headers, cookies)

    return FingerprintResult(
        server=headers.get("Server", "Unknown"),
        powered_by=headers.get("X-Powered-By", "Unknown"),
        technologies=technologies,
        security_headers=security_headers,
        cookie_names=sorted(list(cookies.keys())),
        confidence=confidence,
    )