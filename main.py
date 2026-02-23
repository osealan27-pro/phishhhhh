from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uuid
import asyncio
import socket
import ssl
import httpx
import re
import json
import datetime
from urllib.parse import urlparse

app = FastAPI(title="VulnScan API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store (use Redis/DB in production)
scan_results = {}

class ScanRequest(BaseModel):
    target: str
    verification_token: Optional[str] = None

class VerifyRequest(BaseModel):
    target: str

def normalize_target(target: str) -> str:
    if not target.startswith("http"):
        target = "https://" + target
    return target.rstrip("/")

def extract_host(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    return parsed.hostname

# ─── Scan Modules ────────────────────────────────────────────────────────────

async def check_http_headers(url: str) -> dict:
    """Check security-related HTTP headers."""
    results = []
    score = 0
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            resp = await client.get(url)
            headers = resp.headers

            security_headers = {
                "strict-transport-security": {
                    "name": "HSTS",
                    "severity": "high",
                    "description": "Forces HTTPS connections. Missing = man-in-the-middle risk."
                },
                "content-security-policy": {
                    "name": "CSP",
                    "severity": "high",
                    "description": "Prevents XSS attacks by restricting resource origins."
                },
                "x-frame-options": {
                    "name": "X-Frame-Options",
                    "severity": "medium",
                    "description": "Prevents clickjacking by controlling iframe embedding."
                },
                "x-content-type-options": {
                    "name": "X-Content-Type-Options",
                    "severity": "medium",
                    "description": "Prevents MIME-type sniffing attacks."
                },
                "referrer-policy": {
                    "name": "Referrer-Policy",
                    "severity": "low",
                    "description": "Controls referrer information in requests."
                },
                "permissions-policy": {
                    "name": "Permissions-Policy",
                    "severity": "low",
                    "description": "Controls browser features and APIs access."
                },
                "x-xss-protection": {
                    "name": "X-XSS-Protection",
                    "severity": "low",
                    "description": "Legacy XSS filter (deprecated but still checked)."
                },
            }

            for header_key, info in security_headers.items():
                present = header_key in headers
                if present:
                    score += 1
                results.append({
                    "header": info["name"],
                    "present": present,
                    "severity": info["severity"] if not present else "ok",
                    "value": headers.get(header_key, None),
                    "description": info["description"],
                })

            # Check server header leakage
            server = headers.get("server", "")
            x_powered = headers.get("x-powered-by", "")
            if server:
                results.append({
                    "header": "Server Header Leakage",
                    "present": True,
                    "severity": "medium",
                    "value": server,
                    "description": f"Server reveals: '{server}'. Attackers can target known vulnerabilities."
                })
            if x_powered:
                results.append({
                    "header": "X-Powered-By Leakage",
                    "present": True,
                    "severity": "medium",
                    "value": x_powered,
                    "description": f"Tech stack exposed: '{x_powered}'."
                })

            grade = "A" if score >= 6 else "B" if score >= 4 else "C" if score >= 2 else "F"
            return {"status": "ok", "results": results, "grade": grade, "score": score, "max": len(security_headers)}
    except Exception as e:
        return {"status": "error", "error": str(e), "results": [], "grade": "N/A"}


async def check_ssl(host: str) -> dict:
    """Analyze SSL/TLS certificate."""
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=host
        )
        conn.settimeout(10)
        conn.connect((host, 443))
        cert = conn.getpeercert()
        conn.close()

        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.datetime.utcnow()).days

        issues = []
        if days_left < 30:
            issues.append({"severity": "high", "message": f"Certificate expires in {days_left} days!"})
        if days_left < 0:
            issues.append({"severity": "critical", "message": "Certificate has EXPIRED!"})

        # Check subject
        subject = dict(x[0] for x in cert["subject"])
        issuer = dict(x[0] for x in cert["issuer"])

        san = []
        for ext in cert.get("subjectAltName", []):
            san.append(ext[1])

        return {
            "status": "ok",
            "valid": days_left > 0,
            "days_left": days_left,
            "not_before": str(not_before),
            "not_after": str(not_after),
            "subject": subject.get("commonName", ""),
            "issuer": issuer.get("organizationName", ""),
            "san": san[:10],
            "issues": issues,
            "version": conn.version() if hasattr(conn, 'version') else "TLS"
        }
    except ssl.SSLCertVerificationError as e:
        return {"status": "error", "valid": False, "issues": [{"severity": "critical", "message": f"SSL Verification failed: {e}"}]}
    except Exception as e:
        return {"status": "error", "valid": False, "issues": [{"severity": "info", "message": f"Could not check SSL: {e}"}]}


async def check_ports(host: str) -> dict:
    """Scan common ports."""
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
    }

    dangerous_open = {21, 23, 445, 3389, 5900, 6379, 27017}
    results = []

    async def scan_port(port, service):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=2
            )
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
            severity = "high" if port in dangerous_open else "info"
            return {"port": port, "service": service, "open": True, "severity": severity}
        except:
            return {"port": port, "service": service, "open": False, "severity": "ok"}

    tasks = [scan_port(p, s) for p, s in common_ports.items()]
    results = await asyncio.gather(*tasks)

    open_ports = [r for r in results if r["open"]]
    return {"status": "ok", "results": results, "open_ports": open_ports}


async def check_sensitive_paths(url: str) -> dict:
    """Check for exposed sensitive files and directories."""
    sensitive_paths = [
        ("/.env", "high", "Environment variables (passwords, API keys)"),
        ("/.git/HEAD", "critical", "Git repository exposed (source code leak)"),
        ("/wp-admin/", "medium", "WordPress admin panel"),
        ("/wp-config.php", "critical", "WordPress config file (DB credentials)"),
        ("/phpinfo.php", "high", "PHP info page (server details exposed)"),
        ("/admin/", "medium", "Admin panel"),
        ("/backup/", "high", "Backup directory"),
        ("/config.php", "high", "Config file"),
        ("/robots.txt", "info", "Robots.txt (discloses hidden paths)"),
        ("/.htaccess", "medium", "Apache config exposed"),
        ("/server-status", "medium", "Apache server status"),
        ("/elmah.axd", "high", ".NET error log"),
        ("/.DS_Store", "low", "Mac directory metadata"),
        ("/config.yml", "high", "YAML config file"),
        ("/docker-compose.yml", "high", "Docker config exposed"),
        ("/Makefile", "low", "Makefile exposed"),
        ("/package.json", "low", "Node.js package manifest"),
        ("/.well-known/security.txt", "info", "Security policy (good practice)"),
    ]

    results = []

    async def check_path(path, severity, description):
        try:
            async with httpx.AsyncClient(follow_redirects=False, timeout=5) as client:
                resp = await client.get(url + path)
                found = resp.status_code in [200, 403]
                return {
                    "path": path,
                    "found": found,
                    "status": resp.status_code,
                    "severity": severity if found else "ok",
                    "description": description
                }
        except:
            return {"path": path, "found": False, "status": 0, "severity": "ok", "description": description}

    tasks = [check_path(p, s, d) for p, s, d in sensitive_paths]
    results = await asyncio.gather(*tasks)

    found = [r for r in results if r["found"]]
    return {"status": "ok", "results": results, "found": found}


async def check_dns(host: str) -> dict:
    """Basic DNS info."""
    try:
        ip = socket.gethostbyname(host)
        ips = list(set([r[4][0] for r in socket.getaddrinfo(host, None)]))
        return {"status": "ok", "host": host, "primary_ip": ip, "all_ips": ips}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ─── Background Scan ─────────────────────────────────────────────────────────

async def run_scan(scan_id: str, target: str):
    url = normalize_target(target)
    host = extract_host(target)

    scan_results[scan_id]["status"] = "running"
    scan_results[scan_id]["progress"] = 0

    # DNS
    scan_results[scan_id]["progress"] = 10
    dns = await check_dns(host)
    scan_results[scan_id]["dns"] = dns

    # SSL
    scan_results[scan_id]["progress"] = 25
    ssl_result = await check_ssl(host)
    scan_results[scan_id]["ssl"] = ssl_result

    # HTTP Headers
    scan_results[scan_id]["progress"] = 45
    headers = await check_http_headers(url)
    scan_results[scan_id]["headers"] = headers

    # Sensitive paths
    scan_results[scan_id]["progress"] = 65
    paths = await check_sensitive_paths(url)
    scan_results[scan_id]["paths"] = paths

    # Ports
    scan_results[scan_id]["progress"] = 80
    ports = await check_ports(host)
    scan_results[scan_id]["ports"] = ports

    # Calculate overall risk
    scan_results[scan_id]["progress"] = 100
    scan_results[scan_id]["status"] = "done"
    scan_results[scan_id]["target"] = url
    scan_results[scan_id]["host"] = host
    scan_results[scan_id]["completed_at"] = datetime.datetime.utcnow().isoformat()


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.post("/api/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    host = extract_host(req.target)
    if not host:
        raise HTTPException(400, "Invalid target")

    scan_id = str(uuid.uuid4())
    scan_results[scan_id] = {
        "id": scan_id,
        "status": "queued",
        "progress": 0,
        "target": req.target,
        "created_at": datetime.datetime.utcnow().isoformat()
    }

    background_tasks.add_task(run_scan, scan_id, req.target)
    return {"scan_id": scan_id}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scan_results:
        raise HTTPException(404, "Scan not found")
    return scan_results[scan_id]


@app.get("/api/health")
async def health():
    return {"status": "ok"}
