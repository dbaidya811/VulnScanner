import os
import time
from typing import Dict, Any
from urllib.parse import urlparse


def _normalize_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"


def is_zap_available(timeout: int = 3) -> bool:
    try:
        from zapv2 import ZAPv2  # type: ignore
        api_key = os.environ.get("ZAP_API_KEY", "")
        address = os.environ.get("ZAP_ADDRESS", "127.0.0.1")
        port = int(os.environ.get("ZAP_PORT", "8090"))
        zap = ZAPv2(apikey=api_key, proxies={'http': f'http://{address}:{port}', 'https': f'http://{address}:{port}'})
        version = zap.core.version
        return bool(version)
    except Exception:
        return False


def run_zap_scan(target: str, active: bool = True, timeout: int = 600) -> Dict[str, Any]:
    """
    Run OWASP ZAP passive scan (and optional active scan) against the target URL.
    Requires ZAP daemon running with API enabled.
    Env:
      ZAP_API_KEY, ZAP_ADDRESS (default 127.0.0.1), ZAP_PORT (default 8090)
    """
    from zapv2 import ZAPv2  # type: ignore

    api_key = os.environ.get("ZAP_API_KEY", "")
    address = os.environ.get("ZAP_ADDRESS", "127.0.0.1")
    port = int(os.environ.get("ZAP_PORT", "8090"))

    zap = ZAPv2(apikey=api_key, proxies={'http': f'http://{address}:{port}', 'https': f'http://{address}:{port}'})

    url = _normalize_url(target)

    # Access the target to populate sites tree
    zap.core.access_url(url)

    # Wait for passive scan to complete
    start = time.time()
    while int(zap.pscan.records_to_scan) > 0:
        if time.time() - start > timeout:
            break
        time.sleep(2)

    results: Dict[str, Any] = {"target": url, "passive_alerts": [], "active_scan": None}

    # Collect passive alerts
    alerts = zap.core.alerts(baseurl=url, start=0, count=9999)
    results["passive_alerts"] = alerts

    # Optionally run active scan
    if active:
        scan_id = zap.ascan.scan(url)
        # Poll status
        start = time.time()
        while True:
            status = int(zap.ascan.status(scan_id))
            if status >= 100:
                break
            if time.time() - start > timeout:
                break
            time.sleep(3)
        results["active_scan"] = {
            "scan_id": scan_id,
            "status": int(zap.ascan.status(scan_id)),
            "alerts": zap.core.alerts(baseurl=url, start=0, count=9999),
        }

    return results
