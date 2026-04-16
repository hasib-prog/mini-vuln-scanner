"""
scanner/port_scanner.py
───────────────────────
Multithreaded TCP port scanner.

Scans a configurable range of ports and returns a list of open-port dicts,
each enriched with a service name and a basic vulnerability note if applicable.
"""

import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# ── Service map (port → service name) ─────────────────────────────────────────
SERVICE_MAP: dict[int, str] = {
    20:  "FTP-Data",
    21:  "FTP",
    22:  "SSH",
    23:  "Telnet",
    25:  "SMTP",
    53:  "DNS",
    80:  "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Ports flagged as inherently insecure when open
INSECURE_PORTS: dict[int, dict] = {
    21:   {"severity": "high",   "message": "FTP is open – transfers are unencrypted. Use SFTP/FTPS."},
    23:   {"severity": "critical","message": "Telnet is open – all traffic is plaintext. Use SSH."},
    80:   {"severity": "medium", "message": "Plain HTTP is exposed. Redirect traffic to HTTPS."},
    445:  {"severity": "high",   "message": "SMB is exposed to the internet – high ransomware risk."},
    3389: {"severity": "high",   "message": "RDP is publicly accessible – brute-force & exploit risk."},
    5900: {"severity": "high",   "message": "VNC is open – ensure strong authentication."},
    6379: {"severity": "critical","message": "Redis exposed without auth by default. Restrict access immediately."},
    27017:{"severity": "critical","message": "MongoDB exposed without auth by default. Restrict access immediately."},
}

# Common ports to scan when using 'common' mode
COMMON_PORTS: list[int] = [
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    465, 587, 993, 995, 1433, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 27017,
]


def _probe_port(host: str, port: int, timeout: float) -> dict | None:
    """
    Try to open a TCP connection to host:port.
    Returns a result dict on success, None on failure.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            service = SERVICE_MAP.get(port, "Unknown")
            result = {
                "port": port,
                "state": "open",
                "service": service,
            }
            # Attach vulnerability note if the port is flagged
            if port in INSECURE_PORTS:
                result["vulnerability"] = INSECURE_PORTS[port]
            return result
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_ports(
    host: str,
    port_range: tuple[int, int] | None = None,
    common_only: bool = False,
    timeout: float = 1.0,
    max_workers: int = 100,
) -> list[dict]:
    """
    Scan *host* for open TCP ports.

    Parameters
    ----------
    host        : Resolved IP or hostname.
    port_range  : (start, end) inclusive. Ignored if common_only=True.
    common_only : If True, scan only the predefined COMMON_PORTS list.
    timeout     : Per-port connection timeout in seconds.
    max_workers : Thread pool size.

    Returns a list of open-port dicts sorted by port number.
    """
    if common_only:
        ports = COMMON_PORTS
        logger.info("Port scan: %s – common ports (%d)", host, len(ports))
    else:
        start, end = port_range or (1, 1024)
        start, end = max(1, start), min(65535, end)
        ports = list(range(start, end + 1))
        logger.info("Port scan: %s – ports %d–%d (%d total)", host, start, end, len(ports))

    open_ports: list[dict] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_probe_port, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    logger.info("Port scan complete: %d open ports found on %s", len(open_ports), host)
    return open_ports
