from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _listify(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    return [item for item in value if isinstance(item, dict)]


def _powershell_json(script: str, timeout: int = 45) -> list[dict[str, Any]]:
    wrapped = "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; " + script
    result = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", wrapped],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "PowerShell collector failed").strip()[:1500])
    text = result.stdout.strip().lstrip("\ufeff")
    return _listify(json.loads(text)) if text else []


def _event(source: str, event_type: str, message: str, data: dict[str, Any],
           *, timestamp: str | None = None, severity: str = "info") -> dict[str, Any]:
    return {
        "timestamp": timestamp or utc_now(),
        "source": source,
        "event_type": event_type,
        "severity": severity,
        "host": socket.gethostname(),
        "message": message,
        "data": data,
    }


def collect_system(config: dict[str, Any]) -> list[dict[str, Any]]:
    data = {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "username": os.environ.get("USERNAME", "unknown"),
    }
    return [_event("system", "system", f"System inventory: {data['hostname']}", data)]


def collect_processes(config: dict[str, Any]) -> list[dict[str, Any]]:
    rows = _powershell_json(
        "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate | ConvertTo-Json -Depth 3 -Compress"
    )
    events = []
    for row in rows:
        data = {
            "pid": row.get("ProcessId"),
            "parent_pid": row.get("ParentProcessId"),
            "name": row.get("Name") or "unknown",
            "executable_path": row.get("ExecutablePath") or "",
            "command_line": row.get("CommandLine") or "",
            "creation_time": str(row.get("CreationDate") or ""),
        }
        events.append(_event("process", "process", f"{data['name']} (PID {data['pid']})", data))
    return events


def collect_network(config: dict[str, Any]) -> list[dict[str, Any]]:
    rows = _powershell_json(
        "$p=@{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object {$p[$_.Id]=$_.ProcessName}; "
        "Get-NetTCPConnection -ErrorAction Stop | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{n='ProcessName';e={$p[$_.OwningProcess]}} | ConvertTo-Json -Depth 3 -Compress"
    )
    events = []
    for row in rows:
        data = {
            "local_address": row.get("LocalAddress"),
            "local_port": row.get("LocalPort"),
            "remote_address": row.get("RemoteAddress"),
            "remote_port": row.get("RemotePort"),
            "state": str(row.get("State") or ""),
            "pid": row.get("OwningProcess"),
            "process_name": row.get("ProcessName") or "unknown",
        }
        message = f"{data['process_name']} {data['local_address']}:{data['local_port']} → {data['remote_address']}:{data['remote_port']}"
        events.append(_event("network", "network", message, data))
    return events


def collect_persistence(config: dict[str, Any]) -> list[dict[str, Any]]:
    script = r"""
    $items=@()
    Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | ForEach-Object {
      $items += [pscustomobject]@{Type='startup';Name=$_.Name;Command=$_.Command;Location=$_.Location;User=$_.User;State='enabled'}
    }
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.State -ne 'Disabled'} | Select-Object -First 500 | ForEach-Object {
      $actions=($_.Actions | ForEach-Object {($_.Execute+' '+$_.Arguments).Trim()}) -join '; '
      $items += [pscustomobject]@{Type='scheduled_task';Name=($_.TaskPath+$_.TaskName);Command=$actions;Location=$_.TaskPath;User=$_.Principal.UserId;State=[string]$_.State}
    }
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {$_.StartMode -eq 'Auto'} | ForEach-Object {
      $items += [pscustomobject]@{Type='service';Name=$_.Name;Command=$_.PathName;Location='Service Control Manager';User=$_.StartName;State=$_.State}
    }
    $items | ConvertTo-Json -Depth 4 -Compress
    """
    rows = _powershell_json(script, timeout=75)
    events = []
    for row in rows:
        data = {
            "persistence_type": row.get("Type"),
            "name": row.get("Name") or "unknown",
            "command": row.get("Command") or "",
            "location": row.get("Location") or "",
            "user": row.get("User") or "",
            "state": row.get("State") or "",
        }
        events.append(_event("persistence", "persistence", f"{data['persistence_type']}: {data['name']}", data))
    return events


def collect_windows_events(config: dict[str, Any]) -> list[dict[str, Any]]:
    hours = max(1, min(int(config.get("event_lookback_hours", 24)), 720))
    maximum = max(10, min(int(config.get("max_events_per_log", 250)), 2000))
    script = f"""
    $start=(Get-Date).AddHours(-{hours})
    $logs=@('System','Application','Security','Microsoft-Windows-Windows Defender/Operational','Microsoft-Windows-PowerShell/Operational')
    $out=@()
    foreach($log in $logs){{
      try {{
        Get-WinEvent -FilterHashtable @{{LogName=$log;StartTime=$start}} -MaxEvents {maximum} -ErrorAction Stop | ForEach-Object {{
          $out += [pscustomobject]@{{TimeCreated=$_.TimeCreated.ToUniversalTime().ToString('o');Id=$_.Id;Level=$_.LevelDisplayName;Provider=$_.ProviderName;LogName=$_.LogName;RecordId=$_.RecordId;Message=$_.Message}}
        }}
      }} catch {{}}
    }}
    $out | ConvertTo-Json -Depth 4 -Compress
    """
    rows = _powershell_json(script, timeout=90)
    level_map = {"Critical": "critical", "Error": "high", "Warning": "medium", "Information": "info", "Verbose": "info"}
    events = []
    for row in rows:
        data = {
            "event_id": row.get("Id"),
            "level": row.get("Level") or "Information",
            "provider": row.get("Provider") or "unknown",
            "log_name": row.get("LogName") or "unknown",
            "record_id": row.get("RecordId"),
            "message": (row.get("Message") or "").strip()[:12000],
        }
        message = f"{data['log_name']} / {data['provider']} / Event {data['event_id']}: {data['message'][:500]}"
        events.append(_event("windows_event", "windows_event", message, data,
                             timestamp=str(row.get("TimeCreated") or utc_now()),
                             severity=level_map.get(str(data["level"]), "info")))
    return events


def _default_scan_roots() -> list[Path]:
    roots: list[Path] = []
    user = Path(os.environ.get("USERPROFILE", Path.home()))
    for path in (
        user / "Downloads",
        user / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        Path(os.environ.get("TEMP", user / "AppData" / "Local" / "Temp")),
    ):
        if path.exists():
            roots.append(path)
    return roots


def collect_files(config: dict[str, Any]) -> list[dict[str, Any]]:
    configured = [Path(os.path.expandvars(str(p))).expanduser() for p in config.get("file_scan_roots", [])]
    roots = [p.resolve() for p in configured if p.exists()] or _default_scan_roots()
    max_files = max(1, min(int(config.get("file_scan_max_files", 2000)), 10000))
    max_bytes = max(1024, min(int(config.get("file_scan_max_bytes", 50 * 1024 * 1024)), 512 * 1024 * 1024))
    interesting = {".exe", ".dll", ".sys", ".scr", ".com", ".ps1", ".vbs", ".js", ".jse", ".bat", ".cmd", ".lnk", ".hta", ".msi"}
    events: list[dict[str, Any]] = []
    seen = 0
    for root in roots:
        try:
            candidates = root.rglob("*")
            for path in candidates:
                if seen >= max_files:
                    return events
                try:
                    if not path.is_file() or path.suffix.casefold() not in interesting:
                        continue
                    stat = path.stat()
                    if stat.st_size > max_bytes:
                        continue
                    seen += 1
                    digest = hashlib.sha256()
                    with path.open("rb") as handle:
                        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                            digest.update(chunk)
                    data = {
                        "path": str(path),
                        "name": path.name,
                        "extension": path.suffix.casefold(),
                        "size": stat.st_size,
                        "modified_utc": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(timespec="seconds"),
                        "sha256": digest.hexdigest(),
                        "scan_root": str(root),
                    }
                    events.append(_event("file", "file", f"File triage: {path.name}", data,
                                         timestamp=data["modified_utc"]))
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            continue
    return events


COLLECTORS: dict[str, Callable[[dict[str, Any]], list[dict[str, Any]]]] = {
    "system": collect_system,
    "processes": collect_processes,
    "network": collect_network,
    "persistence": collect_persistence,
    "windows_events": collect_windows_events,
    "files": collect_files,
}


def run_collector(name: str, config: dict[str, Any]) -> list[dict[str, Any]]:
    if name not in COLLECTORS:
        raise KeyError(f"Unknown collector: {name}")
    return COLLECTORS[name](config)
