import time
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import requests
import os
import socket

USER_AGENT = "VulnScanner/1.0 (+https://example.local)"


def _extract_host(target: str) -> str:
    if not re.match(r"^https?://", target):
        target = f"http://{target}"
    p = urlparse(target)
    return p.netloc.split(":")[0]


def _mozilla_observatory(host: str, session: requests.Session, timeout: int = 180) -> Dict[str, Any]:
    # Correct API host (security.mozilla.org)
    base = "https://http-observatory.security.mozilla.org/api/v1"
    try:
        # Try with recommended params first, retry on 5xx with relaxed params
        params_primary = {"host": host, "hidden": "true", "rescan": "true"}
        params_fallback = {"host": host, "hidden": "false", "rescan": "false"}
        last_exc: Optional[Exception] = None
        for attempt, params in enumerate((params_primary, params_fallback, params_primary), start=1):
            try:
                r = session.get(f"{base}/analyze", params=params, timeout=20)
                if 500 <= r.status_code < 600:
                    last_exc = Exception(f"server {r.status_code} on analyze")
                    time.sleep(2 * attempt)
                    continue
                r.raise_for_status()
                data = r.json()
                scan_id = data.get("scan_id")
                # Poll results
                start = time.time()
                result: Optional[Dict[str, Any]] = None
                while time.time() - start < timeout:
                    gr = session.get(f"{base}/getScanResults", params={"scan": scan_id}, timeout=20)
                    if gr.status_code == 200:
                        result = gr.json()
                        if isinstance(result, dict) and result.get("grade") is not None:
                            break
                    elif 500 <= gr.status_code < 600:
                        time.sleep(2)
                    time.sleep(3)
                return {
                    "host": host,
                    "raw": result or data,
                    "grade": (result or {}).get("grade"),
                    "score": (result or {}).get("score"),
                    "tests_failed": (result or {}).get("tests_failed"),
                    "tests_passed": (result or {}).get("tests_passed"),
                    "source": "live",
                }
            except Exception as ie:
                last_exc = ie
                time.sleep(1.5 * attempt)
        # If we get here, retries failed -> try host history as cached fallback
        try:
            hr = session.get(f"{base}/getHostHistory", params={"host": host}, timeout=20)
            if hr.status_code == 200:
                hist = hr.json() or []
                # Expect a list of records with scan_id; pick latest
                if isinstance(hist, list) and hist:
                    latest = hist[0]
                    scan_id = latest.get("scan_id") or latest.get("id")
                    if scan_id:
                        gr = session.get(f"{base}/getScanResults", params={"scan": scan_id}, timeout=20)
                        if gr.status_code == 200:
                            result = gr.json()
                            return {
                                "host": host,
                                "raw": result,
                                "grade": (result or {}).get("grade"),
                                "score": (result or {}).get("score"),
                                "tests_failed": (result or {}).get("tests_failed"),
                                "tests_passed": (result or {}).get("tests_passed"),
                                "source": "history",
                            }
            # Fallthrough -> still error
            return {"host": host, "error": f"Mozilla Observatory temporary issue: {str(last_exc)}"}
        except Exception:
            return {"host": host, "error": f"Mozilla Observatory temporary issue: {str(last_exc)}"}
    except Exception as e:
        return {"host": host, "error": str(e)}


def _ssllabs(host: str, session: requests.Session, timeout: int = 300) -> Dict[str, Any]:
    api = "https://api.ssllabs.com/api/v3/analyze"
    try:
        params = {"host": host, "publish": "off", "fromCache": "on", "all": "done"}
        r = session.get(api, params=params, timeout=20)
        r.raise_for_status()
        data = r.json()
        status = data.get("status")
        start = time.time()
        while status in ("DNS", "IN_PROGRESS", "READY") and status != "READY" and time.time() - start < timeout:
            time.sleep(5)
            r = session.get(api, params={"host": host, "publish": "off"}, timeout=20)
            r.raise_for_status()
            data = r.json()
            status = data.get("status")
        # Summarize endpoints
        endpoints = []
        for ep in (data.get("endpoints") or []):
            endpoints.append({
                "ipAddress": ep.get("ipAddress"),
                "grade": ep.get("grade"),
                "statusMessage": ep.get("statusMessage"),
                "serverName": ep.get("serverName"),
            })
        return {"host": host, "status": status, "endpoints": endpoints, "raw": data if status == "READY" else None}
    except Exception as e:
        return {"host": host, "error": str(e)}


def _crtsh(host: str, session: requests.Session) -> Dict[str, Any]:
    try:
        r = session.get("https://crt.sh/", params={"q": host, "output": "json"}, timeout=20)
        if r.status_code != 200:
            return {"host": host, "error": f"crt.sh status {r.status_code}"}
        try:
            data = r.json()
        except Exception:
            # Sometimes crt.sh returns text/html; do a best-effort parse later if needed
            data = []
        names: List[str] = []
        for row in data:
            name = row.get("name_value")
            if name:
                for part in str(name).split("\n"):
                    names.append(part.strip())
        # Unique, sorted
        uniq = sorted({n.lower() for n in names if n})
        # Filter wildcards to the end
        uniq = sorted(uniq, key=lambda x: (x.startswith("*"), x))
        return {"host": host, "count": len(uniq), "names": uniq[:50]}
    except Exception as e:
        return {"host": host, "error": str(e)}


def run_cloud_scan(target: str) -> Dict[str, Any]:
    host = _extract_host(target)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    mo = _mozilla_observatory(host, session)
    ssl = _ssllabs(host, session)
    crt = _crtsh(host, session)

    # Optional: urlscan.io (requires URLSCAN_API_KEY)
    urlscan_key = os.environ.get("URLSCAN_API_KEY")
    urlscan: Dict[str, Any] = {"skipped": True, "reason": "No URLSCAN_API_KEY set"}
    if urlscan_key:
        urlscan = _urlscan_scan(host, session, urlscan_key)

    # Optional: Shodan (requires SHODAN_API_KEY). If not available or membership blocked, fall back to InternetDB
    shodan_key = os.environ.get("SHODAN_API_KEY")
    shodan: Dict[str, Any] = {"skipped": True, "reason": "No SHODAN_API_KEY set"}
    if shodan_key:
        shodan = _shodan_lookup(host, session, shodan_key)
    if isinstance(shodan, dict) and (shodan.get("error", "").startswith("host lookup failed: 401") or
                                      shodan.get("error", "").startswith("host lookup failed: 403") or
                                      shodan.get("error", "").startswith("dns resolve failed: 403")):
        # Fall back to InternetDB free endpoint
        try:
            ip_fallback = shodan.get("ip")
            if not ip_fallback:
                try:
                    ip_fallback = socket.gethostbyname(host)
                except Exception:
                    ip_fallback = None
            if ip_fallback:
                shodan = _internetdb_lookup(ip_fallback, session)
        except Exception:
            pass

    return {
        "host": host,
        "mozilla_observatory": mo,
        "ssl_labs": ssl,
        "crtsh": crt,
        "urlscan": urlscan,
        "shodan": shodan,
    }


def _urlscan_scan(host: str, session: requests.Session, api_key: str, timeout: int = 180) -> Dict[str, Any]:
    """Submit a scan to urlscan.io and fetch the result summary."""
    try:
        url = f"http://{host}"
        headers = {"API-Key": api_key, "Content-Type": "application/json", "User-Agent": USER_AGENT}
        submit = session.post("https://urlscan.io/api/v1/scan", json={"url": url, "visibility": "public"}, headers=headers, timeout=20)
        if submit.status_code not in (200, 201):
            return {"error": f"urlscan submit failed: {submit.status_code} {submit.text[:120]}"}
        j = submit.json()
        result_url = j.get("api") or j.get("result")
        uuid = j.get("uuid")
        # Poll result
        start = time.time()
        res_json: Optional[Dict[str, Any]] = None
        while time.time() - start < timeout:
            r = session.get(result_url, headers={"User-Agent": USER_AGENT}, timeout=20)
            if r.status_code == 200:
                try:
                    res_json = r.json()
                    if res_json.get("page"):
                        break
                except Exception:
                    pass
            time.sleep(3)
        if not res_json:
            return {"uuid": uuid, "warning": "urlscan result not ready in time"}
        # Summarize minimal fields
        page = res_json.get("page", {})
        lists = res_json.get("lists", {})
        summary = {
            "uuid": uuid,
            "url": page.get("url"),
            "country": page.get("country"),
            "server": page.get("server"),
            "ip": page.get("ip"),
            "domains": (lists.get("domains") or [])[:20],
            "ips": (lists.get("ips") or [])[:10],
        }
        return summary
    except Exception as e:
        return {"error": str(e)}


def _shodan_lookup(host: str, session: requests.Session, api_key: str) -> Dict[str, Any]:
    """Resolve host to IP via Shodan and fetch host info for each IP (limited summary)."""
    try:
        # Resolve hostname to IPs using Shodan DNS resolve
        r = session.get("https://api.shodan.io/dns/resolve", params={"hostnames": host, "key": api_key}, timeout=20)
        if r.status_code != 200:
            return {"error": f"dns resolve failed: {r.status_code} {r.text[:120]}"}
        mapping = r.json() or {}
        ip = mapping.get(host)
        if not ip:
            # fallback: local DNS
            try:
                ip = socket.gethostbyname(host)
            except Exception:
                return {"error": "could not resolve host"}
        # Host info
        r2 = session.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": api_key}, timeout=30)
        if r2.status_code != 200:
            return {"ip": ip, "error": f"host lookup failed: {r2.status_code} {r2.text[:120]}"}
        data = r2.json()
        # Summarize
        ports = data.get("ports") or []
        org = data.get("org")
        isp = data.get("isp")
        vulns = list((data.get("vulns") or {}).keys())[:20]
        return {"ip": ip, "org": org, "isp": isp, "ports": ports[:30], "vulns": vulns, "source": "shodan"}
    except Exception as e:
        return {"error": str(e)}


def _internetdb_lookup(ip: str, session: requests.Session) -> Dict[str, Any]:
    """Use Shodan's free InternetDB endpoint (no API key) for basic intel."""
    try:
        r = session.get(f"https://internetdb.shodan.io/{ip}", timeout=20)
        if r.status_code != 200:
            return {"ip": ip, "error": f"internetdb failed: {r.status_code} {r.text[:120]}"}
        data = r.json()
        return {
            "ip": ip,
            "ports": (data.get("ports") or [])[:30],
            "vulns": (data.get("vulns") or [])[:20],
            "source": "internetdb"
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}
