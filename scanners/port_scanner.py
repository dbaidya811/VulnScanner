import socket
from typing import Dict, Any, List, Tuple

COMMON_PORTS: List[Tuple[int, str]] = [
    (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"), (53, "dns"),
    (80, "http"), (110, "pop3"), (111, "rpcbind"), (135, "msrpc"), (139, "netbios-ssn"),
    (143, "imap"), (443, "https"), (445, "microsoft-ds"), (3306, "mysql"), (3389, "rdp"),
    (5900, "vnc"), (6379, "redis"), (8080, "http-alt"), (8443, "https-alt"), (9200, "elasticsearch"),
]


def run_port_scan(target: str, timeout: float = 0.5) -> Dict[str, Any]:
    """Simple TCP connect scan over a list of common ports."""
    open_ports: List[Dict[str, Any]] = []
    for port, name in COMMON_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((target, port))
                if result == 0:
                    service = name
                    try:
                        service = socket.getservbyport(port)
                    except Exception:
                        pass
                    open_ports.append({"port": port, "service": service})
        except Exception:
            # Ignore per-port exceptions to keep scanning
            continue
    return {"open_ports": sorted(open_ports, key=lambda x: x["port"]) }
