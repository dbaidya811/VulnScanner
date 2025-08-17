import json
import os
import shutil
import subprocess
from typing import Dict, Any, Optional


def _parse_nmap_xml_to_simple(text: str) -> Dict[str, Any]:
    # Fallback minimal parse if XML; better to use -oX and xmltodict, but avoid extra deps.
    # We'll just return raw output.
    return {"raw_output": text}


def _resolve_nmap_path() -> Optional[str]:
    """Resolve nmap executable path.
    Order: NMAP_PATH env -> PATH -> common Windows install paths.
    """
    # 1) Env var
    env_path = os.environ.get("NMAP_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path
    # 2) PATH
    found = shutil.which("nmap")
    if found:
        return found
    # 3) Common Windows locations
    candidates = [
        r"C:\\Program Files (x86)\\Nmap\\nmap.exe",
        r"C:\\Program Files\\Nmap\\nmap.exe",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def run_nmap_scan(target: str) -> Dict[str, Any]:
    """
    Run an nmap scan against target. Tries python-nmap if available, otherwise uses subprocess.
    Returns a dictionary of results.
    """
    try:
        import nmap  # type: ignore
        scanner = nmap.PortScanner()
        # Fast reasonable scan: service/version, common scripts
        scanner.scan(targets=target, arguments="-sS -sV -T4 -Pn --top-ports 1000")
        result: Dict[str, Any] = {"hosts": []}
        for host in scanner.all_hosts():
            host_data = {
                "host": host,
                "state": scanner[host].state(),
                "protocols": {},
            }
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                host_data["protocols"][proto] = []
                for port in sorted(ports):
                    entry = scanner[host][proto][port]
                    host_data["protocols"][proto].append({
                        "port": port,
                        "state": entry.get("state"),
                        "name": entry.get("name"),
                        "product": entry.get("product"),
                        "version": entry.get("version"),
                        "extrainfo": entry.get("extrainfo"),
                    })
            result["hosts"].append(host_data)
        return result
    except Exception:
        # Fallback to subprocess
        nmap_exe = _resolve_nmap_path()
        if not nmap_exe:
            raise RuntimeError(
                "nmap is not installed or not found. Install Nmap and either add it to PATH or set NMAP_PATH to nmap.exe"
            )
        try:
            completed = subprocess.run(
                [nmap_exe, "-sS", "-sV", "-T4", "-Pn", "--top-ports", "1000", target],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if completed.returncode != 0:
                raise RuntimeError(completed.stderr.strip() or "nmap failed")
            return {"raw_output": completed.stdout}
        except subprocess.TimeoutExpired:
            raise RuntimeError("nmap scan timed out")
