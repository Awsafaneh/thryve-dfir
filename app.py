from __future__ import annotations

import ctypes
import base64
import binascii
import hashlib
import io
import json
import mimetypes
import os
import re
import socket
import subprocess
import sys
import threading
import traceback
import webbrowser
import zipfile
import urllib.request
import urllib.error
import shutil
import math
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from aegis import __version__
from aegis.collectors import COLLECTORS, run_collector
from aegis.database import Database, canonical_json, utc_now
from aegis.detectors import evaluate
from aegis.reporting import build_pdf_report


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DATA = ROOT / "data"
CONFIG_PATH = ROOT / "config.json"
RULES_PATH = ROOT / "rules.json"
DB = Database(DATA / "aegis.db")
CONFIG: dict[str, Any] = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
DB.seed_rules(json.loads(RULES_PATH.read_text(encoding="utf-8")))
COLLECTION_LOCK = threading.Lock()


def seed_demo_data() -> None:
    """Create clearly synthetic, repeatable showcase telemetry for Cloud Run demos."""
    if os.environ.get("THRYVE_DEMO_DATA", "").lower() not in {"1", "true", "yes"}:
        return
    host = "AWS-ANALYST-01"
    user = "AWS\\analyst"
    now = datetime.now(UTC).replace(microsecond=0)
    samples = [
        ("windows_event", "windows_event", "Security 7045: service installed: TelemetrySync", "high", {"event_id": "7045", "channel": "System", "provider": "Service Control Manager", "service_name": "TelemetrySync", "account": "LocalSystem", "user": user}),
        ("windows_event", "windows_event", "Security 4698: scheduled task created: UpdateHealth", "high", {"event_id": "4698", "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing", "task_name": "\\UpdateHealth", "user": user}),
        ("windows_event", "windows_event", "Security 4624: successful interactive logon", "info", {"event_id": "4624", "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing", "logon_type": "2", "user": user}),
        ("process", "process", "powershell.exe -EncodedCommand observed", "high", {"name": "powershell.exe", "pid": 2844, "ppid": 912, "user": user, "command_line": "powershell.exe -NoProfile -EncodedCommand <synthetic-demo-payload>", "executable_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "signed": True}),
        ("process", "process", "rundll32.exe launched from Downloads", "high", {"name": "rundll32.exe", "pid": 3116, "ppid": 2844, "user": user, "command_line": "rundll32.exe C:\\Users\\analyst\\Downloads\\report-viewer.dll,Start", "executable_path": "C:\\Users\\analyst\\Downloads\\rundll32.exe", "signed": True}),
        ("network", "network", "Established connection to rare destination", "medium", {"protocol": "TCP", "local_address": "10.20.4.18:53122", "remote_address": "198.51.100.44:4444", "remote_port": "4444", "state": "ESTABLISHED", "process": "rundll32.exe", "pid": 3116, "user": user}),
        ("persistence", "persistence", "Automatic service points to AppData", "high", {"persistence_type": "service", "name": "TelemetrySync", "command": "C:\\Users\\analyst\\AppData\\Local\\TelemetrySync\\sync.exe --service", "user": user, "status": "auto-start"}),
        ("windows_event", "windows_event", "Defender 1116: synthetic malware detection", "critical", {"event_id": "1116", "channel": "Microsoft-Windows-Windows Defender/Operational", "provider": "Microsoft-Windows-Windows Defender", "threat_name": "Demo.Test.Detection", "user": user}),
    ]
    events = []
    for index, (source, event_type, message, severity, data) in enumerate(samples):
        data = {**data, "demo": True, "dataset": "THRYVE_SYNTHETIC_SHOWCASE", "host": host}
        events.append({"timestamp": (now - timedelta(minutes=index * 7)).isoformat(), "source": source, "event_type": event_type, "severity": severity, "host": host, "message": f"[DEMO DATA] {message}", "data": data})
    inserted = DB.insert_events(events)
    alerts = evaluate(inserted, DB.enabled_rules())
    if alerts:
        DB.insert_alerts(alerts)


seed_demo_data()


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def risk_score(overview: dict[str, Any]) -> int:
    severity = overview.get("alert_severity", {})
    raw = (
        int(severity.get("critical", 0)) * 28
        + int(severity.get("high", 0)) * 14
        + int(severity.get("medium", 0)) * 5
        + int(severity.get("low", 0)) * 2
    )
    return min(100, raw)


def build_export(case_id: int | None) -> tuple[bytes, str]:
    payload = DB.export_rows(case_id)
    evidence = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str).encode("utf-8")
    evidence_hash = hashlib.sha256(evidence).hexdigest()
    manifest = {
        "tool": "Thryve",
        "version": __version__,
        "exported_at": utc_now(),
        "hostname": socket.gethostname(),
        "case_id": case_id,
        "files": [{"name": "evidence.json", "sha256": evidence_hash, "bytes": len(evidence)}],
        "integrity_note": "Verify SHA-256 before and after evidence transfer.",
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("evidence.json", evidence)
        archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8"))
        archive.writestr("README.txt", "Thryve evidence package\r\nVerify evidence.json against manifest.json before analysis.\r\n")
    suffix = f"case-{case_id}" if case_id is not None else "snapshot"
    return buffer.getvalue(), f"thryve-{suffix}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.zip"


def gemini_analyze(prompt: str, evidence: dict[str, Any]) -> str:
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not configured. Set it in the local process environment.")
    model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    instruction = (
        "You are the Thryve defensive SOC copilot for an OWASP Amman demonstration. "
        "Analyze only the supplied evidence. Never claim certainty, never invent telemetry, and never give offensive instructions. "
        "Return concise Markdown with exactly these sections: Assessment, Evidence, MITRE Context, Recommended Defensive Actions, Confidence. "
        "Use English. Recommend safe validation, containment, and documentation steps.\n\n"
        f"Analyst request: {prompt[:2000]}\n\nEvidence JSON:\n{json.dumps(evidence, ensure_ascii=False, default=str)[:24000]}"
    )
    body = json.dumps({"contents": [{"parts": [{"text": instruction}]}], "generationConfig": {"temperature": 0.2, "maxOutputTokens": 900}}).encode()
    request = urllib.request.Request(endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:1000]
        raise RuntimeError(f"Gemini request failed ({exc.code}): {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Gemini network error: {exc.reason}") from exc
    try:
        return payload["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("Gemini returned no usable analysis") from exc


TEXT_ATTACHMENT_SUFFIXES = {".txt", ".log", ".json", ".csv", ".md", ".xml", ".yml", ".yaml", ".ps1", ".py", ".js", ".html"}


def gemini_chat(prompt: str, history: list[dict[str, Any]], attachments: list[dict[str, Any]]) -> str:
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not configured. Set it in the local process environment.")
    if not prompt:
        raise ValueError("A question is required")
    overview = DB.overview()
    environment = {
        "overview": overview,
        "recent_alerts": DB.list_alerts(limit=12)["items"],
        "recent_events": DB.list_events(limit=15)["items"],
        "active_rules": [rule for rule in DB.rules() if rule.get("enabled")][:50],
    }
    prior = [{"role": str(item.get("role", "user"))[:12], "content": str(item.get("content", ""))[:1500]} for item in history[-8:]]
    instruction = (
        "You are Thryve Analyst Chat, a defensive DFIR assistant. Use only the supplied endpoint context, conversation, and selected attachments. "
        "Be precise about what is observed versus inferred. Never fabricate evidence or claim a file is malicious without support. "
        "Do not provide offensive instructions. Give concise English answers with practical validation, containment, or documentation steps when appropriate.\n\n"
        f"Endpoint context JSON:\n{json.dumps(environment, ensure_ascii=False, default=str)[:45000]}\n\n"
        f"Conversation JSON:\n{json.dumps(prior, ensure_ascii=False)[:12000]}\n\n"
        f"Analyst question:\n{prompt[:4000]}"
    )
    parts: list[dict[str, Any]] = [{"text": instruction}]
    total = 0
    for attachment in attachments[:4]:
        name = str(attachment.get("name", "attachment"))[:180]
        mime = str(attachment.get("mime", "application/octet-stream"))[:120]
        encoded = str(attachment.get("data", ""))
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError(f"Invalid attachment encoding: {name}") from exc
        total += len(raw)
        if len(raw) > 4 * 1024 * 1024 or total > 6 * 1024 * 1024:
            raise ValueError("Attachments exceed the 6 MB analysis limit")
        suffix = Path(name).suffix.lower()
        if mime.startswith("image/"):
            parts.append({"inlineData": {"mimeType": mime, "data": encoded}})
            parts.append({"text": f"Image attachment: {name}. Analyze it only in relation to the analyst question."})
        elif suffix in TEXT_ATTACHMENT_SUFFIXES:
            parts.append({"text": f"Text attachment: {name}\n---\n{raw.decode('utf-8', 'replace')[:80000]}\n---"})
        elif suffix == ".pdf":
            try:
                from pypdf import PdfReader
                pdf_text = "\n".join((page.extract_text() or "") for page in PdfReader(io.BytesIO(raw)).pages[:20])[:80000]
            except Exception:
                pdf_text = ""
            parts.append({"text": f"PDF attachment: {name}\n---\n{pdf_text or '[Text extraction unavailable]'}\n---"})
        else:
            parts.append({"text": f"Attachment metadata only: {name} ({mime}, {len(raw)} bytes). Binary content was not sent for analysis."})
    model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    request = urllib.request.Request(endpoint, data=json.dumps({"contents": [{"parts": parts}], "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1200}}).encode(), headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return payload["candidates"][0]["content"]["parts"][0]["text"]
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Gemini request failed ({exc.code})") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Gemini network error: {exc.reason}") from exc
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("Gemini returned no usable analysis") from exc


MEMORY_PLUGINS = {
    "windows.pslist": "Process listing",
    "windows.pstree": "Process tree",
    "windows.netscan": "Network sockets",
    "windows.cmdline": "Process command lines",
    "windows.dlllist": "Loaded modules",
    "windows.registry.hivelist": "Registry hives",
    "windows.malfind": "Executable memory regions",
}


def memory_status() -> dict[str, Any]:
    volatility = shutil.which("vol") or shutil.which("vol.py")
    try:
        import volatility3  # noqa: F401
        package = True
    except ImportError:
        package = False
    return {"available": bool(volatility or package), "command": volatility, "package": package, "plugins": MEMORY_PLUGINS}


def memory_analyze(image_path: str, plugin: str) -> dict[str, Any]:
    target = Path(image_path).expanduser().resolve(strict=True)
    if not target.is_file():
        raise ValueError("Memory image path must be a file")
    if plugin not in MEMORY_PLUGINS:
        raise ValueError("Unsupported memory plugin")
    command = shutil.which("vol") or shutil.which("vol.py")
    if command:
        args = [command, "-f", str(target), plugin, "-q"]
    else:
        try:
            import volatility3  # noqa: F401
        except ImportError as exc:
            raise RuntimeError("Install Volatility 3 before analyzing memory images") from exc
        args = [sys.executable, "-m", "volatility3", "-f", str(target), plugin, "-q"]
    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"plugin": plugin, "label": MEMORY_PLUGINS[plugin], "image": str(target), "returncode": result.returncode,
            "stdout": result.stdout[-50000:], "stderr": result.stderr[-10000:], "sha256": digest.hexdigest()}


def forensic_tools() -> list[dict[str, Any]]:
    import importlib.util
    definitions = [
        ("Velociraptor", "Endpoint collection", "velociraptor", None, "Client/server endpoint visibility", "external"),
        ("Volatility 3", "Memory forensics", "vol", "volatility3", "Windows memory plugins", "local"),
        ("Autopsy", "Disk forensics", "autopsy", None, "Case-based disk-image analysis", "external"),
        ("The Sleuth Kit", "Filesystem forensics", "fls", None, "Volume and filesystem evidence", "local"),
        ("Hayabusa", "Windows event hunting", "hayabusa", None, "EVTX detections and timelines", "local"),
        ("Chainsaw", "EVTX threat hunting", "chainsaw", None, "Windows artifact hunting", "local"),
        ("Plaso", "Timeline analysis", "log2timeline", None, "Multi-artifact super timelines", "local"),
        ("Timesketch", "Collaborative timeline", "timesketch", None, "Timeline review platform", "external"),
        ("Zeek", "Network analysis", "zeek", None, "Network security monitoring logs", "local"),
        ("Wireshark", "Packet analysis", "tshark", None, "PCAP inspection", "local"),
        ("Suricata", "Network detection", "suricata", None, "IDS and network monitoring", "local"),
        ("Arkime", "Packet indexing", "arkime-capture", None, "Full-packet capture and search", "external"),
        ("capa", "Static capability analysis", "capa", "capa", "Executable capability identification", "local"),
        ("FLOSS", "String analysis", "floss", "floss", "Obfuscated-string extraction", "local"),
        ("Ghidra", "Reverse engineering", "analyzeHeadless", None, "Software reverse engineering", "external"),
        ("CyberChef", "Data transformation", "cyberchef", None, "Offline data decoding and analysis", "external"),
        ("osquery", "Endpoint telemetry", "osqueryi", None, "SQL endpoint instrumentation", "local"),
        ("Sigma", "Detection engineering", "sigma", "sigma", "Portable detection rules", "local"),
        ("ALEAPP", "Mobile forensics", "aleapp", None, "Android artifact parsing", "local"),
        ("MVT", "Mobile forensics", "mvt", "mvt", "Mobile compromise indicators", "local"),
        ("pefile", "Portable executable triage", None, "pefile", "PE headers, imports, sections", "embedded"),
        ("YARA", "Pattern scanning", "yara", "yara", "Rule-based file scanning", "embedded"),
        ("ExifTool", "Metadata extraction", "exiftool", None, "Document and media metadata", "local"),
        ("Bulk Extractor", "Artifact extraction", "bulk_extractor", None, "Feature extraction from evidence", "local"),
    ]
    items = []
    for name, area, command, module, capability, integration in definitions:
        available = memory_status()["available"] if name == "Volatility 3" else bool((command and shutil.which(command)) or (module and importlib.util.find_spec(module)))
        items.append({"name": name, "area": area, "available": available, "capability": capability, "integration": integration})
    return items


def forensic_file_triage(file_path: str) -> dict[str, Any]:
    target = Path(file_path).expanduser().resolve(strict=True)
    if not target.is_file():
        raise ValueError("Artifact path must be a file")
    stat = target.stat()
    if stat.st_size > 512 * 1024 * 1024:
        raise ValueError("Artifact exceeds the 512 MB triage safety limit")
    digest = hashlib.sha256()
    printable = bytearray()
    histogram = [0] * 256
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            for value in chunk:
                histogram[value] += 1
            if len(printable) < 256_000:
                printable.extend(chunk[:256_000 - len(printable)])
    total = sum(histogram)
    entropy = -sum((count / total) * math.log2(count / total) for count in histogram if count) if total else 0
    strings = re.findall(rb"[\x20-\x7e]{6,}", bytes(printable))[:80]
    result: dict[str, Any] = {"path": str(target), "name": target.name, "bytes": stat.st_size, "sha256": digest.hexdigest(),
                              "modified_utc": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(timespec="seconds"),
                              "entropy": round(entropy, 3), "strings": [item.decode("utf-8", "replace") for item in strings], "pe": None}
    if target.suffix.lower() in {".exe", ".dll", ".sys", ".scr", ".cpl"}:
        try:
            import pefile
            pe = pefile.PE(str(target), fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            imports = []
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:60]:
                imports.append(entry.dll.decode("utf-8", "replace"))
            result["pe"] = {"machine": hex(pe.FILE_HEADER.Machine), "timestamp": pe.FILE_HEADER.TimeDateStamp,
                            "sections": [{"name": section.Name.rstrip(b"\\0").decode("utf-8", "replace"), "entropy": round(section.get_entropy(), 3)} for section in pe.sections],
                            "imports": imports}
        except Exception as exc:
            result["pe"] = {"error": str(exc)[:400]}
    return result


YARA_QUICK_RULES = r'''
rule thryve_encoded_powershell : execution suspicious {
  strings:
    $encoded = "-enc " ascii nocase
    $encoded2 = "-encodedcommand" ascii nocase
  condition:
    any of them
}

rule thryve_lolbin_execution : execution suspicious {
  strings:
    $rundll32 = "rundll32.exe" ascii nocase
    $regsvr32 = "regsvr32.exe" ascii nocase
    $mshta = "mshta.exe" ascii nocase
  condition:
    any of them
}
'''


def forensic_yara_scan(file_path: str) -> dict[str, Any]:
    target = Path(file_path).expanduser().resolve(strict=True)
    if not target.is_file():
        raise ValueError("Artifact path must be a file")
    if target.stat().st_size > 512 * 1024 * 1024:
        raise ValueError("Artifact exceeds the 512 MB scan safety limit")
    try:
        import yara
    except ImportError as exc:
        raise RuntimeError("YARA is not installed") from exc
    matches = yara.compile(source=YARA_QUICK_RULES).match(str(target), timeout=30)
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    findings = []
    for match in matches:
        hits = []
        for string in match.strings[:20]:
            for instance in string.instances[:5]:
                hits.append({"identifier": string.identifier, "offset": instance.offset, "length": instance.matched_length})
        findings.append({"rule": match.rule, "tags": list(match.tags), "hits": hits})
    return {"path": str(target), "sha256": digest.hexdigest(), "rule_set": "Thryve defensive quick rules v1", "matches": findings}


class AegisHandler(BaseHTTPRequestHandler):
    server_version = "Thryve/0.1"

    def log_message(self, format: str, *args: Any) -> None:
        sys.stdout.write(f"[{self.log_date_time_string()}] {format % args}\n")

    def _headers(self, status: int, content_type: str, length: int | None = None,
                 disposition: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if length is not None:
            self.send_header("Content-Length", str(length))
        if disposition:
            self.send_header("Content-Disposition", disposition)
        self.send_header("Cache-Control", "no-store" if content_type.startswith("application/json") else "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()

    def json_response(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def error_json(self, status: int, message: str, detail: str | None = None) -> None:
        payload = {"ok": False, "error": message}
        if detail:
            payload["detail"] = detail[:2000]
        self.json_response(payload, status)

    def read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length") from exc
        if length < 0 or length > 8_388_608:
            raise ValueError("Request body is too large")
        if length == 0:
            return {}
        value = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    @staticmethod
    def query_int(query: dict[str, list[str]], key: str, default: int) -> int:
        try:
            return int(query.get(key, [str(default)])[0])
        except (TypeError, ValueError):
            return default

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        try:
            if path.startswith("/api/"):
                self.handle_api_get(path, query)
            else:
                self.serve_static(path)
        except BrokenPipeError:
            return
        except Exception as exc:
            traceback.print_exc()
            self.error_json(500, "Internal server error", str(exc))

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if not path.startswith("/api/"):
            self.error_json(404, "Route not found")
            return
        try:
            body = self.read_json()
            self.handle_api_post(path, body)
        except ValueError as exc:
            self.error_json(400, "Invalid request", str(exc))
        except Exception as exc:
            traceback.print_exc()
            self.error_json(500, "Internal server error", str(exc))

    def handle_api_get(self, path: str, query: dict[str, list[str]]) -> None:
        if path == "/api/status":
            self.json_response({
                "ok": True,
                "version": __version__,
                "hostname": socket.gethostname(),
                "admin": is_admin(),
                "bind": f"{CONFIG.get('bind', '127.0.0.1')}:{CONFIG.get('port', 8765)}",
                "database": str(DB.path),
                "collectors": list(COLLECTORS),
                "collection_busy": COLLECTION_LOCK.locked(),
                "server_time": utc_now(),
            })
            return
        if path == "/api/memory/status":
            self.json_response(memory_status())
            return
        if path == "/api/forensics/tools":
            self.json_response({"items": forensic_tools()})
            return
        if path == "/api/overview":
            result = DB.overview()
            result["risk_score"] = risk_score(result)
            result["host"] = socket.gethostname()
            result["admin"] = is_admin()
            self.json_response(result)
            return
        if path in {"/api/events", "/api/processes", "/api/network", "/api/persistence", "/api/files", "/api/timeline"}:
            event_type_map = {
                "/api/processes": "process", "/api/network": "network", "/api/persistence": "persistence",
                "/api/files": "file", "/api/timeline": None,
            }
            event_type = event_type_map.get(path) or query.get("type", [None])[0]
            result = DB.list_events(
                source=query.get("source", [None])[0], event_type=event_type,
                severity=query.get("severity", [None])[0], query=query.get("q", [None])[0],
                limit=self.query_int(query, "limit", 200), offset=self.query_int(query, "offset", 0),
            )
            self.json_response(result)
            return
        if path == "/api/alerts":
            self.json_response(DB.list_alerts(
                status=query.get("status", [None])[0], severity=query.get("severity", [None])[0],
                query=query.get("q", [None])[0], limit=self.query_int(query, "limit", 200),
                offset=self.query_int(query, "offset", 0),
            ))
            return
        if path == "/api/rules":
            self.json_response({"items": DB.rules(), "total": len(DB.rules())})
            return
        if path == "/api/collections":
            self.json_response({"items": DB.recent_collections()})
            return
        if path == "/api/cases":
            self.json_response({"items": DB.list_cases()})
            return
        match = re.fullmatch(r"/api/cases/(\d+)", path)
        if match:
            case = DB.get_case(int(match.group(1)))
            if not case:
                self.error_json(404, "Case not found")
            else:
                self.json_response(case)
            return
        if path == "/api/search":
            q = query.get("q", [""])[0].strip()
            if not q:
                self.json_response({"query": q, "events": [], "alerts": []})
            else:
                self.json_response({
                    "query": q,
                    "events": DB.list_events(query=q, limit=100)["items"],
                    "alerts": DB.list_alerts(query=q, limit=100)["items"],
                })
            return
        if path == "/api/settings":
            self.json_response({k: CONFIG[k] for k in (
                "event_lookback_hours", "max_events_per_log", "max_table_rows",
                "file_scan_roots", "file_scan_max_files", "file_scan_max_bytes",
            ) if k in CONFIG})
            return
        if path == "/api/export":
            case_id = self.query_int(query, "case_id", 0) or None
            try:
                body, filename = build_export(case_id)
            except KeyError:
                self.error_json(404, "Case not found")
                return
            self._headers(200, "application/zip", len(body), f'attachment; filename="{filename}"')
            self.wfile.write(body)
            return
        if path == "/api/report.pdf":
            case_id = self.query_int(query, "case_id", 0) or None
            try:
                report = build_pdf_report(DB.overview(), DB.export_rows(case_id), socket.gethostname(), case_id)
            except KeyError:
                self.error_json(404, "Case not found")
                return
            suffix = f"case-{case_id}" if case_id is not None else "endpoint-snapshot"
            filename = f"thryve-{suffix}-report-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.pdf"
            self._headers(200, "application/pdf", len(report), f'attachment; filename="{filename}"')
            self.wfile.write(report)
            return
        self.error_json(404, "API route not found")

    def handle_api_post(self, path: str, body: dict[str, Any]) -> None:
        if path == "/api/memory/analyze":
            image = str(body.get("image_path", "")).strip()
            plugin = str(body.get("plugin", "windows.pslist"))
            self.json_response({"ok": True, "result": memory_analyze(image, plugin)})
            return
        if path == "/api/forensics/file-triage":
            self.json_response({"ok": True, "result": forensic_file_triage(str(body.get("path", "")).strip())})
            return
        if path == "/api/forensics/yara-scan":
            self.json_response({"ok": True, "result": forensic_yara_scan(str(body.get("path", "")).strip())})
            return
        if path == "/api/ai/analyze":
            prompt = str(body.get("prompt", "Analyze the current incident.")).strip()
            evidence = body.get("evidence")
            if not isinstance(evidence, dict):
                evidence = DB.overview()
            self.json_response({"ok": True, "model": os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"), "analysis": gemini_analyze(prompt, evidence)})
            return
        if path == "/api/ai/chat":
            history = body.get("history", [])
            attachments = body.get("attachments", [])
            if not isinstance(history, list) or not isinstance(attachments, list):
                raise ValueError("history and attachments must be lists")
            self.json_response({"ok": True, "model": os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"), "analysis": gemini_chat(str(body.get("prompt", "")).strip(), history, attachments)})
            return
        if path == "/api/collect":
            requested = body.get("collectors", body.get("collector", "all"))
            if requested == "all":
                names = list(COLLECTORS)
            elif isinstance(requested, str):
                names = [requested]
            elif isinstance(requested, list):
                names = [str(item) for item in requested]
            else:
                raise ValueError("collectors must be a name, list, or 'all'")
            unknown = [name for name in names if name not in COLLECTORS]
            if unknown:
                raise ValueError(f"Unknown collectors: {', '.join(unknown)}")
            if not COLLECTION_LOCK.acquire(blocking=False):
                self.error_json(409, "Another collection is already running")
                return
            results: list[dict[str, Any]] = []
            total_alerts = 0
            try:
                for name in names:
                    collection_id = DB.collection_start(name)
                    try:
                        collected = run_collector(name, CONFIG)
                        inserted = DB.insert_events(collected)
                        alerts = evaluate(inserted, DB.enabled_rules())
                        alert_count = DB.insert_alerts(alerts)
                        total_alerts += alert_count
                        DB.collection_finish(collection_id, "complete", len(inserted))
                        results.append({"collector": name, "status": "complete", "collected": len(collected), "inserted": len(inserted), "alerts": alert_count})
                    except Exception as exc:
                        DB.collection_finish(collection_id, "failed", 0, str(exc))
                        results.append({"collector": name, "status": "failed", "error": str(exc)[:1000]})
            finally:
                COLLECTION_LOCK.release()
            self.json_response({"ok": True, "results": results, "new_alerts": total_alerts})
            return
        if path == "/api/cases":
            title = str(body.get("title", "")).strip()
            if not title:
                raise ValueError("title is required")
            severity = str(body.get("severity", "medium"))
            if severity not in {"low", "medium", "high", "critical"}:
                raise ValueError("invalid severity")
            self.json_response(DB.create_case(title, str(body.get("description", "")), severity), 201)
            return
        match = re.fullmatch(r"/api/cases/(\d+)/items", path)
        if match:
            item_type = str(body.get("item_type", "note"))
            if item_type not in {"note", "alert", "event", "file"}:
                raise ValueError("invalid item_type")
            item_id = body.get("item_id")
            if item_id is not None:
                item_id = int(item_id)
            if DB.add_case_item(int(match.group(1)), item_type, item_id, str(body.get("note", ""))):
                self.json_response({"ok": True}, 201)
            else:
                self.error_json(404, "Case not found")
            return
        match = re.fullmatch(r"/api/alerts/(\d+)/status", path)
        if match:
            if DB.update_alert_status(int(match.group(1)), str(body.get("status", ""))):
                self.json_response({"ok": True})
            else:
                self.error_json(400, "Invalid status or alert not found")
            return
        match = re.fullmatch(r"/api/rules/([^/]+)/toggle", path)
        if match:
            rule_id = unquote(match.group(1))
            if DB.toggle_rule(rule_id, bool(body.get("enabled", True))):
                self.json_response({"ok": True})
            else:
                self.error_json(404, "Rule not found")
            return
        if path == "/api/file/hash":
            raw_path = str(body.get("path", "")).strip()
            if not raw_path:
                raise ValueError("path is required")
            target = Path(raw_path).expanduser().resolve(strict=True)
            if not target.is_file():
                raise ValueError("path must be a file")
            digest = hashlib.sha256()
            with target.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            stat = target.stat()
            self.json_response({"path": str(target), "sha256": digest.hexdigest(), "size": stat.st_size,
                                "modified_utc": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(timespec="seconds")})
            return
        self.error_json(404, "API route not found")

    def serve_static(self, path: str) -> None:
        relative = "index.html" if path == "/" else unquote(path.lstrip("/"))
        target = (STATIC / relative).resolve()
        try:
            target.relative_to(STATIC.resolve())
        except ValueError:
            self.error_json(403, "Path is not allowed")
            return
        if not target.is_file():
            target = STATIC / "index.html"
        if not target.is_file():
            self.error_json(503, "Frontend files are not available")
            return
        body = target.read_bytes()
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"}:
            content_type += "; charset=utf-8"
        self._headers(200, content_type, len(body))
        self.wfile.write(body)


def main() -> None:
    # Cloud Run supplies PORT and requires a public container listener. Local
    # Windows runs remain loopback-only unless HOST is explicitly provided.
    host = os.environ.get("HOST", str(CONFIG.get("bind", "127.0.0.1")))
    port = int(os.environ.get("PORT", CONFIG.get("port", 8765)))
    if host not in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}:
        raise SystemExit("Unsupported bind address.")
    server = ThreadingHTTPServer((host, port), AegisHandler)
    url = f"http://{host}:{port}/"
    print(f"Thryve {__version__} running at {url}")
    print(f"Administrator: {'yes' if is_admin() else 'no'} | Database: {DB.path}")
    if "--no-browser" not in sys.argv:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Thryve...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
