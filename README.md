# Thryve

Thryve is a local-first Windows SOC/SIEM and digital-forensics workbench. It collects endpoint telemetry into a local SQLite database, runs transparent detection rules, provides an English analyst console, and exports integrity-verifiable evidence packages.

## What it includes

- Windows event collection from System, Application, Security, Defender, and PowerShell logs.
- Process inventory with PID, parent PID, path, command line, and creation time.
- TCP connection inventory mapped to owning processes.
- Persistence inventory covering startup commands, scheduled tasks, and automatic services.
- Targeted file triage in Downloads, Startup, and Temp with SHA-256 hashing.
- Rule-based detections with MITRE ATT&CK mappings.
- Alert triage states, IOC/full-text search, investigation cases, notes, and timelines.
- ZIP evidence export containing `evidence.json` and a SHA-256 manifest.
- Downloadable PDF evidence reports with an executive summary, risk score, alert register, evidence timeline, and page-numbered handling guidance.
- A DFIR workbench with Volatility 3 memory plugins, bounded file-artifact triage, and readiness checks for YARA, ExifTool, Plaso, and Hayabusa.
- Local-only HTTP binding (`127.0.0.1`) and no remote JavaScript, fonts, or analytics.

## Run it

Requirements: Windows 10/11 and Python 3.11 or newer. No third-party Python packages are required.

For normal collection:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\start.ps1
```

For complete access to Security logs and process details, right-click PowerShell, choose **Run as administrator**, then:

```powershell
.\start.ps1
```

Alternatively, use `.\start-admin.ps1` to request elevation. The console opens at <http://127.0.0.1:8765>.

## Gemini SOC copilot

The Incident Storyline view includes an optional Gemini defensive analyst action. Keep the key out of source files and browser JavaScript. In the same PowerShell window used to start Thryve, set:

```powershell
$env:GEMINI_API_KEY = "your-key"
$env:GEMINI_MODEL = "gemini-2.5-flash"
.\start.ps1
```

The key is used only by the local backend for `/api/ai/analyze`; the UI sends the selected alert evidence, not your whole database. If the variable is absent, the feature stays available but reports a clear configuration message.

## First collection

Open the dashboard and choose **Full Collection**. A full pass can take one or two minutes because Windows event and persistence queries are intentionally bounded but thorough. Individual collectors can be run from the quick-actions area.

## Configuration

Edit `config.json` while the service is stopped:

- `event_lookback_hours`: Windows Event Log lookback window (1–720).
- `max_events_per_log`: maximum events collected from each log (10–2000).
- `file_scan_roots`: optional explicit local directories. When empty, Thryve scans the current user's Downloads, Startup, and Temp directories.
- `file_scan_max_files`: maximum interesting executable/script files hashed per pass.
- `file_scan_max_bytes`: maximum size of each file hashed.

Detection rules live in `rules.json`. Each rule has a source, field, operator (`equals`, `contains`, `in`, or `regex`), value, severity, and optional MITRE technique. Rules can be enabled or disabled from the dashboard. Restart after editing rule definitions on disk.

## Evidence handling

Case and snapshot exports are ZIP files. Always verify the SHA-256 value for `evidence.json` against `manifest.json` before and after transfer. Thryve provides collection integrity metadata but is not a substitute for write blockers, forensic disk imaging, or your organization's chain-of-custody procedure.

## Security model

Thryve intentionally listens only on loopback and refuses a non-local bind. This initial release has no remote authentication or TLS; do not expose it through port forwarding or a reverse proxy. Collection uses fixed PowerShell scripts, and the web API does not accept arbitrary commands.

## DFIR workbench

The workbench is deliberately local and evidence-led: it never fabricates a finding. **Memory Lab** runs a fixed allow-list of Volatility 3 Windows plugins (`pslist`, `pstree`, `netscan`, `cmdline`, `dlllist`, `hivelist`, and `malfind`) against an analyst-selected image and records the image SHA-256 with the result. **File Artifact Triage** calculates SHA-256, entropy, printable strings, timestamps, and PE import/section metadata without executing the submitted file.

The readiness panel detects optional open-source tools on the analyst workstation. This keeps licensing, versioning, and chain-of-custody decisions explicit: Thryve adapts installed tools rather than bundling unknown binaries. YARA, capa, ExifTool, Plaso, Hayabusa, Chainsaw, and Bulk Extractor are shown as ready only when they are actually installed. The included YARA quick scan uses small, transparent defensive rules for encoded PowerShell and selected Windows LOLBins; it is an initial triage signal, not a malware verdict.

The integrated tool registry covers Velociraptor, Volatility 3, Autopsy, The Sleuth Kit, Hayabusa, Chainsaw, Plaso, Timesketch, Zeek, Wireshark, Suricata, Arkime, capa, FLOSS, Ghidra, CyberChef, osquery, Sigma, ALEAPP, and MVT. Tools marked **External** are platforms or GUI/server products and are intentionally not launched from Thryve; tools marked **Optional** need a verified local installation; **Ready** means the executable or Python module was discovered on this workstation.

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Important limitations

- This is a strong endpoint triage and single-host SIEM foundation, not a replacement for enterprise EDR or a multi-tenant SIEM cluster.
- Memory acquisition, full-disk imaging, browser-history parsers, PCAP capture, remote agents, and threat-intelligence enrichment are outside this first local release. The workbench exposes only tools that are verifiably present on the workstation.
- Some Security events are available only when Windows auditing policies are enabled before the relevant activity occurs.
