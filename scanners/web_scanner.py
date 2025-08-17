from typing import Dict, Any, List
from urllib.parse import urljoin, urlparse
import re
import requests
from bs4 import BeautifulSoup


USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"


def normalize_url(target: str) -> str:
    if not re.match(r"^https?://", target):
        return f"http://{target}"
    return target


def run_basic_web_scan(target: str, timeout: int = 10, max_links: int = 25) -> Dict[str, Any]:
    """
    Basic HTTP checks:
    - Fetch homepage
    - Extract limited set of internal links
    - Check security headers on each
    - Look for common sensitive files (robots.txt, .git, .env)
    """
    start_url = normalize_url(target)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    results: Dict[str, Any] = {
        "start_url": start_url,
        "pages": [],
        "sensitive_files": [],
    }

    try:
        resp = session.get(start_url, timeout=timeout, allow_redirects=True)
        main_url = resp.url
        soup = BeautifulSoup(resp.text, "html.parser")
        results["homepage_status"] = resp.status_code
        results["final_url"] = main_url

        domain = urlparse(main_url).netloc
        links: List[str] = []
        for a in soup.find_all("a", href=True):
            href = a.get("href")
            url = urljoin(main_url, href)
            p = urlparse(url)
            if p.netloc == domain and p.scheme in ("http", "https"):
                links.append(url)
        # Unique, limited
        seen = set()
        filtered = []
        for u in links:
            if u not in seen:
                seen.add(u)
                filtered.append(u)
            if len(filtered) >= max_links:
                break

        # Include the homepage itself first
        crawl = [main_url] + filtered

        def check_headers(headers: Dict[str, str]) -> Dict[str, Any]:
            missing = []
            recommended = [
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
                "Strict-Transport-Security",
            ]
            present = {k: headers.get(k) for k in recommended if headers.get(k)}
            for k in recommended:
                if k not in headers:
                    missing.append(k)
            return {"present": present, "missing": missing}

        for url in crawl:
            try:
                r = session.get(url, timeout=timeout)
                hdrs = {k: v for k, v in r.headers.items()}
                sec = check_headers(hdrs)
                results["pages"].append({
                    "url": url,
                    "status": r.status_code,
                    "security_headers": sec,
                })
            except Exception as e:
                results["pages"].append({
                    "url": url,
                    "error": str(e),
                })

        # Check common sensitive files
        sensitive = ["/robots.txt", "/.env", "/.git/HEAD", "/server-status", "/phpinfo.php"]
        for path in sensitive:
            url = urljoin(main_url, path)
            try:
                r = session.get(url, timeout=timeout)
                if r.status_code < 400:
                    results["sensitive_files"].append({"url": url, "status": r.status_code})
            except Exception:
                continue

        return results
    except Exception as e:
        raise RuntimeError(f"Web scan failed: {e}")
