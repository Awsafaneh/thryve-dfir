"use strict";

const API = {
  status: "/api/status", overview: "/api/overview", alerts: "/api/alerts",
  events: "/api/events", processes: "/api/processes", network: "/api/network",
  persistence: "/api/persistence", rules: "/api/rules", collect: "/api/collect",
  search: "/api/search", cases: "/api/cases", export: "/api/export", report: "/api/report.pdf", chat: "/api/ai/chat"
};

const state = {
  activeView: "overview", cache: {}, status: {}, overview: {}, tables: {},
  pageSize: Number(localStorage.getItem("aegis_page_size")) || 50,
  refreshSeconds: Number(localStorage.getItem("aegis_refresh")) || 60,
  privacyMode: localStorage.getItem("aegis_privacy_mode") === "true",
  refreshTimer: null, selectedRecord: null, selectedRecordType: null, selectedCase: null, storyAlerts: [],
  chat: { threads: [], activeId: null, messages: [], attachments: [] }
};

const CHAT_STORAGE_KEY = "thryve_analyst_chat_threads_v1";

const viewConfig = {
  alerts: {
    code: "ALERTS / 03", title: "Alerts", subtitle: "Triage detections by severity, status, and MITRE ATT&CK technique.",
    filterLabel: "All severities", filterKey: "severity", filters: [["", "All severities"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]],
    columns: [
      ["severity", "Severity", severityCell], ["title", "Alert", titleCell], ["source", "Source", textCell],
      ["mitre", "MITRE", monoCell], ["timestamp", "Time", timeCell], ["status", "Status", stateCell]
    ]
  },
  events: {
    code: "EVENTS / 04", title: "Events", subtitle: "Unified Windows telemetry from local sources.",
    filterKey: "channel", filters: [["", "All channels"], ["Security", "Security"], ["System", "System"], ["PowerShell", "PowerShell"], ["Sysmon", "Sysmon"]],
    columns: [
      ["timestamp", "Time", timeCell], ["event_id", "Event ID", monoCell], ["channel", "Channel", textCell],
      ["provider", "Provider", textCell], ["message", "Event summary", titleCell], ["computer", "Host", hostCell]
    ]
  },
  processes: {
    code: "PROCESSES / 05", title: "Processes", subtitle: "Process snapshot, ancestry, command lines, and signatures.",
    filterKey: "risk", filters: [["", "All assessments"], ["suspicious", "Suspicious"], ["unsigned", "Unsigned"], ["normal", "Normal"]],
    columns: [
      ["name", "Process", titleCell], ["pid", "PID", monoCell], ["ppid", "PPID", monoCell], ["user", "User", userCell],
      ["command_line", "Command line", commandCell], ["signed", "Signature", signedCell], ["risk", "Assessment", riskCell]
    ]
  },
  network: {
    code: "NETWORK / 06", title: "Network", subtitle: "Local and remote connections mapped to owning processes.",
    filterKey: "state", filters: [["", "All states"], ["ESTABLISHED", "ESTABLISHED"], ["LISTENING", "LISTENING"], ["TIME_WAIT", "TIME_WAIT"]],
    columns: [
      ["protocol", "Protocol", monoCell], ["local_address", "Local address", monoCell], ["remote_address", "Destination", monoCell],
      ["state", "State", stateCell], ["process", "Process", titleCell], ["pid", "PID", monoCell], ["timestamp", "Observed", timeCell]
    ]
  },
  persistence: {
    code: "PERSISTENCE / 07", title: "Persistence", subtitle: "Autoruns, services, scheduled tasks, and startup entries.",
    filterKey: "type", filters: [["", "All types"], ["service", "Service"], ["scheduled_task", "Scheduled task"], ["registry", "Registry"], ["startup", "Startup"]],
    columns: [
      ["type", "Type", typeCell], ["name", "Name", titleCell], ["path", "Path / command", commandCell],
      ["user", "Context", userCell], ["status", "Status", stateCell], ["risk", "Assessment", riskCell], ["timestamp", "Last change", timeCell]
    ]
  },
  rules: {
    code: "RULES / 09", title: "Detection Rules", subtitle: "Local detection coverage mapped to MITRE ATT&CK techniques.",
    filterKey: "enabled", filters: [["", "All rules"], ["true", "Enabled"], ["false", "Disabled"]],
    columns: [
      ["enabled", "Status", enabledCell], ["name", "Rule", titleCell], ["description", "Description", textCell],
      ["severity", "Severity", severityCell], ["mitre", "MITRE", monoCell], ["hits", "Hits", monoCell], ["source", "Source", textCell]
    ]
  }
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const escapeHtml = value => String(value ?? "").replace(/[&<>'"]/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[char]));
const pick = (obj, keys, fallback = "—") => {
  for (const key of keys) {
    if (obj && obj[key] !== undefined && obj[key] !== null && obj[key] !== "") return obj[key];
  }
  return fallback;
};
const asArray = (payload, preferred = []) => {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== "object") return [];
  for (const key of [...preferred, "items", "results", "data", "records", "rows"]) if (Array.isArray(payload[key])) return payload[key];
  return [];
};
const number = value => Number.isFinite(Number(value)) ? Number(value) : 0;
const fmt = value => new Intl.NumberFormat("en-US", { notation: number(value) > 999999 ? "compact" : "standard", maximumFractionDigits: 1 }).format(number(value));
const escapeRegExp = value => String(value).replace(/[.*+?^${}()|[\]\\]/g,"\\$&");

function maskDisplay(value, kind = "generic") {
  const raw = String(value ?? "—");
  if (!state.privacyMode) return raw;
  if (raw === "—" || raw === "") return raw;
  if (kind === "host") return "HOST-REDACTED";
  if (kind === "user") return "USER-REDACTED";
  if (kind === "path") return raw === "—" ? raw : "[LOCAL PATH MASKED]";
  let output = raw.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g,"IP-REDACTED");
  output = output.replace(/\b(?:[A-Fa-f0-9]{1,4}:){2,}[A-Fa-f0-9:]*\b/g,"IP-REDACTED");
  const host = pick(state.status,["hostname","host","computer_name","device_name"],"");
  if (host && host !== "—") output = output.replace(new RegExp(`\\b${escapeRegExp(host)}\\b`,"gi"),"HOST-REDACTED");
  if (/(?:[A-Za-z]:\\|\\\\)/.test(output)) output = "[LOCAL PATH MASKED]";
  return output;
}

function redactedClone(value, key = "") {
  if (!state.privacyMode) return value;
  if (Array.isArray(value)) return value.map(item => redactedClone(item,key));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([childKey,child]) => [childKey,redactedClone(child,childKey)]));
  if (typeof value !== "string") return value;
  if (/host|computer|device_name/i.test(key)) return maskDisplay(value,"host");
  if (/user|owner|account|username/i.test(key)) return maskDisplay(value,"user");
  if (/path|command|executable|database|evidence_path/i.test(key)) return maskDisplay(value,"path");
  return maskDisplay(value);
}

async function request(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeout || 15000);
  try {
    const response = await fetch(url, {
      ...options, signal: controller.signal,
      headers: { "Accept": "application/json", ...(options.body ? {"Content-Type":"application/json"} : {}), ...(options.headers || {}) }
    });
    if (!response.ok) {
      let detail = "";
      const errorBody = await response.text();
      try {
        const parsed = JSON.parse(errorBody);
        detail = parsed.detail || parsed.message || parsed.error || "";
      } catch { detail = errorBody; }
      if (/[\u0600-\u06FF]/.test(detail)) detail = "The local engine rejected this request.";
      throw new Error(detail || `HTTP ${response.status}`);
    }
    if (response.status === 204) return {};
    const contentType = response.headers.get("content-type") || "";
    return contentType.includes("json") ? response.json() : response.text();
  } catch (error) {
    if (error.name === "AbortError") throw new Error("The local service timed out");
    throw error;
  } finally { clearTimeout(timer); }
}

function setText(id, value) { const el = document.getElementById(id); if (el) el.textContent = value ?? "—"; }
function setSensitiveText(id,value,kind){setText(id,maskDisplay(value,kind));}
function normalizedSeverity(value) {
  const v = String(value || "info").toLowerCase();
  if (v.includes("critical")) return "critical";
  if (v.includes("high")) return "high";
  if (["medium","warning"].some(x => v.includes(x))) return "medium";
  if (["healthy","good","ok"].some(x => v.includes(x))) return "healthy";
  return v === "low" ? "low" : "info";
}
function severityLabel(value) { return ({critical:"CRITICAL",high:"HIGH",medium:"MEDIUM",low:"LOW",info:"INFO",healthy:"HEALTHY"})[normalizedSeverity(value)] || String(value || "INFO").toUpperCase(); }
function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("en-GB", { month:"short", day:"2-digit", hour:"2-digit", minute:"2-digit", hour12:false }).format(date);
}
function formatFullTime(value) {
  if (!value) return "—";
  const date = new Date(value); if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("en-GB", { dateStyle:"medium", timeStyle:"medium", hour12:false }).format(date);
}

function titleCell(value) { return `<strong>${escapeHtml(maskDisplay(value))}</strong>`; }
function textCell(value) { return escapeHtml(maskDisplay(value)); }
function monoCell(value) { return `<span class="ltr-cell">${escapeHtml(maskDisplay(value))}</span>`; }
function hostCell(value) { return `<span class="ltr-cell sensitive-host">${escapeHtml(maskDisplay(value,"host"))}</span>`; }
function userCell(value) { return escapeHtml(maskDisplay(value,"user")); }
function timeCell(value) { return `<time class="ltr-cell" title="${escapeHtml(formatFullTime(value))}">${escapeHtml(formatTime(value))}</time>`; }
function severityCell(value) { const s = normalizedSeverity(value); return `<span class="severity ${s}">${severityLabel(s)}</span>`; }
function stateCell(value) { const v = String(value ?? "—"); const cl = /open|new|established|active/i.test(v) ? "open" : /closed|resolved|done|healthy/i.test(v) ? "closed" : ""; return `<span class="state-chip ${cl}">${escapeHtml(v)}</span>`; }
function commandCell(value) { const raw=String(value ?? "—"),v=maskDisplay(raw,"path"); return `<span class="ltr-cell" title="${escapeHtml(v)}">${escapeHtml(v.length > 52 ? `${v.slice(0,52)}…` : v)}</span>`; }
function riskCell(value) { const v = String(value ?? "normal"); const s = /susp|high|critical/i.test(v) ? "high" : /medium|warn|unsigned/i.test(v) ? "medium" : "healthy"; return `<span class="severity ${s}">${escapeHtml(v)}</span>`; }
function signedCell(value) { if(value===null||value===undefined||value==="—")return `<span class="state-chip">Unavailable</span>`;const yes = value === true || /true|valid|signed/i.test(String(value)); return `<span class="severity ${yes ? "healthy" : "medium"}">${yes ? "SIGNED" : "UNSIGNED"}</span>`; }
function typeCell(value) { return `<span class="state-chip">${escapeHtml(String(value ?? "—").replaceAll("_"," "))}</span>`; }
function enabledCell(value) { const yes = value === true || String(value).toLowerCase() === "true" || value === 1; return `<span class="severity ${yes ? "healthy" : "info"}">${yes ? "ENABLED" : "DISABLED"}</span>`; }

function normalizeItem(type, item) {
  const common = { ...(item?.data && typeof item.data === "object" ? item.data : {}), ...item };
  item = common;
  if (type === "alerts") Object.assign(common, {
    title: pick(item,["title","name","rule_name","message","description"]), severity: pick(item,["severity","level","risk"]),
    source: pick(item,["source","provider","channel"]), mitre: pick(item,["mitre","technique","mitre_technique","attack_id"]),
    timestamp: pick(item,["timestamp","time","created_at","detected_at"]), status: pick(item,["status","state"],"open")
  });
  if (type === "events") Object.assign(common, {
    timestamp: pick(item,["timestamp","time","created_at"]), event_id: pick(item,["event_id","eventId","id"]),
    channel: pick(item,["channel","log_name","source"]), provider: pick(item,["provider","provider_name"]),
    message: pick(item,["message","description","summary"]), computer: pick(item,["computer","hostname","host"])
  });
  if (type === "processes") Object.assign(common, {
    name: pick(item,["name","process_name","image"]), pid: pick(item,["pid","process_id"]), ppid: pick(item,["ppid","parent_pid"]),
    user: pick(item,["user","username","owner"]), command_line: pick(item,["command_line","cmdline","command","path"]),
    signed: pick(item,["signed","is_signed","signature_valid"],null), risk: pick(item,["risk","status","assessment"],"normal")
  });
  if (type === "network") Object.assign(common, {
    protocol: pick(item,["protocol","proto"]), local_address: joinAddress(item,"local"), remote_address: joinAddress(item,"remote"),
    state: pick(item,["state","status"]), process: pick(item,["process","process_name","name"]), pid: pick(item,["pid","process_id"]), timestamp: pick(item,["timestamp","time","observed_at"])
  });
  if (type === "persistence") Object.assign(common, {
    type: pick(item,["type","persistence_type","category","kind"]), name: pick(item,["name","entry_name","display_name"]), path: pick(item,["path","command","value","image_path"]),
    user: pick(item,["user","context","account"]), status: pick(item,["status","state"],"detected"), risk: pick(item,["risk","severity","assessment"],"normal"), timestamp: pick(item,["timestamp","modified_at","last_changed"])
  });
  if (type === "rules") Object.assign(common, {
    enabled: pick(item,["enabled","active","is_enabled"],false), name: pick(item,["name","title","rule_name"]), description: pick(item,["description","summary"]),
    severity: pick(item,["severity","level"]), mitre: pick(item,["mitre","technique","attack_id"]), hits: pick(item,["hits","match_count","count"]), source: pick(item,["source","category","type"])
  });
  return common;
}
function joinAddress(item, side) {
  const combined = pick(item,[`${side}_endpoint`,side],null);
  if (combined !== null) return combined;
  const ip = pick(item,[`${side}_address`,`${side}_ip`,`${side}_addr`],""); const port = pick(item,[`${side}_port`],"");
  return port !== "" ? `${ip}:${port}` : (ip || "—");
}

function showNotice(error) {
  $("#apiNotice").classList.remove("hidden");
  setText("apiNoticeText", `${error?.message || "The local service is unavailable"}. Thryve never substitutes sample telemetry.`);
}
function hideNotice() { $("#apiNotice").classList.add("hidden"); }
function toast(title, detail = "", kind = "") {
  const el = document.createElement("div"); el.className = `toast ${kind}`; el.innerHTML = `<b>${escapeHtml(title)}</b>${detail ? `<span>${escapeHtml(detail)}</span>` : ""}`;
  $("#toastRegion").append(el); setTimeout(() => { el.classList.add("out"); setTimeout(() => el.remove(), 250); }, 4000);
}

async function loadCore({quiet = false} = {}) {
  const settled = await Promise.allSettled([request(API.status), request(API.overview)]);
  let failed = false;
  if (settled[0].status === "fulfilled") { state.status = settled[0].value || {}; renderStatus(state.status); } else failed = true;
  if (settled[1].status === "fulfilled") { state.overview = settled[1].value || {}; renderOverview(state.overview); } else failed = true;
  if (failed) showNotice(settled.find(x => x.status === "rejected")?.reason); else hideNotice();
  if (!quiet) setText("settingsLastSync", formatFullTime(new Date()));
}

function renderStatus(data) {
  const host = pick(data,["hostname","host","computer_name","device_name"]);
  const healthy = Boolean(pick(data,["collector_healthy","healthy","collector_running","ok"],false));
  const collector = data.collection_busy ? "Collecting" : pick(data,["collector_status","status","collector"],healthy ? "Ready" : "Unavailable");
  setSensitiveText("hostName",host,"host"); setSensitiveText("sideHost",host,"host"); setText("hostOs",pick(data,["os","os_version","platform"],"Windows"));
  setText("engineVersion",pick(data,["version","engine_version"]));
  setText("collectorState",collector); $("#collectorState").insertAdjacentHTML("afterbegin", `<i class="status-dot ${healthy ? "good" : "bad"}"></i> `);
  setText("ingestionState",pick(data,["ingestion_state","ingestion","mode"],data.collection_busy ? "INGESTION BUSY" : healthy ? "ENGINE READY" : "ENGINE STOPPED"));
  setText("bindAddress",pick(data,["bind","bind_address","listen_address"],"127.0.0.1"));
  setSensitiveText("evidencePath",pick(data,["database","evidence_path","data_path"],"Local / managed by engine"),"path");
}

function renderOverview(data) {
  const counts = data.counts || data.stats || data.kpis || data;
  const alerts = asArray(data,["recent_alerts","alerts"]);
  const severityCounts = data.alert_severity || {};
  const explicitCriticalHigh = pick(counts,["critical_high_alerts","critical_high"],null);
  const critical = explicitCriticalHigh !== null ? explicitCriticalHigh : number(pick(counts,["alerts_critical","critical_alerts"],severityCounts.critical)) + number(pick(counts,["alerts_high","high_alerts"],severityCounts.high));
  const eventTotal = pick(counts,["events","event_count","total_events"],0);
  const alertTotal = pick(counts,["alerts","alert_count","total_alerts","alerts_open"],alerts.length);
  const suspicious = pick(counts,["suspicious_processes","process_alerts","suspicious_process_count"],0);
  const connections = pick(counts,["active_connections","connections","network_connections"],0);
  setText("kpiCritical",fmt(critical)); setText("kpiEvents",fmt(eventTotal)); setText("kpiProcesses",fmt(suspicious)); setText("kpiConnections",fmt(connections));
  setText("pulseEvents",fmt(eventTotal)); setText("pulseAlerts",fmt(alertTotal)); setText("navAlertCount",fmt(alertTotal));
  const risk = Math.max(0,Math.min(100,number(pick(data,["risk_score","score","threat_score"],0))));
  setText("riskScore",risk); setText("riskLabel", risk >= 75 ? "Critical review required" : risk >= 50 ? "High review priority" : risk >= 25 ? "Analyst review recommended" : "No elevated risk");
  const riskColor = risk >= 75 ? "var(--red)" : risk >= 40 ? "var(--amber)" : risk > 0 ? "var(--cyan)" : "var(--line)";
  const collections=asArray(data,["collections"]);const lastCollection=collections[0]||{};
  $("#riskRing").style.borderTopColor = riskColor; setText("lastScan",`Last collection: ${formatTime(pick(data,["last_scan","last_collection","updated_at"],pick(lastCollection,["finished_at","started_at"],state.status.last_scan)))}`);
  renderRecentAlerts(alerts.slice(0,8));
  renderStoryline(alerts);
  const sources = asArray(data,["sources","coverage","collectors","collections"]); renderCoverage(data,sources);
  const volumes = asArray(data,["event_volume","volume","timeline"]).map(v => typeof v === "number" ? v : number(pick(v,["count","value","events"],0)));
  renderSpark(volumes); drawEventChart(volumes); setText("eventRate",`${fmt(pick(data,["event_rate","events_per_minute"],volumes.at(-1) || 0))} evt/min`);
}

function renderRecentAlerts(alerts) {
  const body = $("#recentAlerts");
  if (!alerts.length) { body.innerHTML = `<tr><td colspan="6"><div class="empty-state small"><span>✓</span><b>No alerts</b><p>The engine returned no alerts in the current scope.</p></div></td></tr>`; return; }
  body.innerHTML = alerts.map((raw,index) => {
    const item = normalizeItem("alerts",raw); state.cache[`recent-${index}`] = item;
    return `<tr data-row="recent-${index}" tabindex="0"><td>${severityCell(item.severity)}</td><td>${titleCell(item.title)}</td><td>${textCell(item.source)}</td><td>${monoCell(item.mitre)}</td><td>${timeCell(item.timestamp)}</td><td>${stateCell(item.status)}</td></tr>`;
  }).join("");
}

function renderStoryline(alerts, selectedIndex = 0) {
  const select = $("#storyAlertSelect"), content = $("#storylineContent");
  if (!select || !content) return;
  state.storyAlerts = alerts.map(item => normalizeItem("alerts",item));
  if (!state.storyAlerts.length) {
    select.innerHTML = `<option>No live alerts</option>`; select.disabled = true;
    content.innerHTML = `<div class="empty-state"><span>✓</span><b>No alert selected</b><p>Select an alert to review its linked evidence and detection context.</p></div>`;
    return;
  }
  select.disabled = false;
  select.innerHTML = state.storyAlerts.map((item,index) => `<option value="${index}" ${index===selectedIndex?"selected":""}>${escapeHtml(severityLabel(item.severity))} · ${escapeHtml(maskDisplay(item.title))}</option>`).join("");
  const item = state.storyAlerts[Math.min(selectedIndex,state.storyAlerts.length-1)];
  const evidenceMessage = pick(item,["message","description","summary"],"");
  const eventId = pick(item,["event_id","record_id"],"");
  const correlation = evidenceMessage && evidenceMessage !== "—" ? maskDisplay(evidenceMessage) : eventId ? `Linked event ${eventId} from ${maskDisplay(item.source)}.` : "No linked evidence detail was returned by the API.";
  const technique = item.mitre && item.mitre !== "—" ? item.mitre : "Not mapped by the active rule";
  const action = ["critical","high"].includes(normalizedSeverity(item.severity)) ? "Validate the linked evidence, scope adjacent activity, and open a case before containment." : "Validate the signal and document disposition in an investigation case.";
  content.innerHTML = `<div class="storyline-ai-bar"><button class="primary-button" type="button" id="aiAnalyzeStory">✦ Ask Gemini to analyze this incident</button><span id="aiStoryStatus">Evidence stays local except the selected alert sent to Gemini.</span></div><div class="storyline-grid">
    <article class="story-step"><span class="story-number">01 / SIGNAL</span><h3>${escapeHtml(maskDisplay(item.title))}</h3><p>${escapeHtml(severityLabel(item.severity))} alert observed from ${escapeHtml(maskDisplay(item.source))}.</p><span class="story-evidence">${escapeHtml(formatFullTime(item.timestamp))}</span></article>
    <article class="story-step"><span class="story-number">02 / CORRELATION</span><h3>Evidence context</h3><p>${escapeHtml(correlation)}</p><span class="story-evidence">${eventId ? `EVENT ${escapeHtml(eventId)}` : "API EVIDENCE ONLY"}</span></article>
    <article class="story-step"><span class="story-number">03 / MITRE TECHNIQUE</span><h3>${escapeHtml(technique)}</h3><p>${item.mitre && item.mitre!=="—" ? "Mapped by the detection rule that produced this alert." : "No technique mapping was returned for this alert."}</p><span class="story-evidence">RULE ${escapeHtml(pick(item,["rule_id"],"UNAVAILABLE"))}</span></article>
    <article class="story-step"><span class="story-number">04 / ANALYST ACTION</span><h3>Recommended next step</h3><p>${escapeHtml(action)}</p><span class="story-evidence">RECOMMENDATION · NOT TELEMETRY</span></article>
  </div><div id="aiStoryResult" class="ai-result hidden"></div>`;
  $("#aiAnalyzeStory").addEventListener("click",()=>analyzeStoryWithGemini(item));
}

function cleanExternalAnalysis(value){return String(value||"").replace(/\\([#*`_])/g,"$1").replace(/^#{1,6}\s*/gm,"").replace(/`([^`]+)`/g,"$1").trim();}
function chatId(){return `chat-${Date.now().toString(36)}-${Math.random().toString(36).slice(2,8)}`;}
function chatTitle(messages){const first=messages.find(message=>message.role==="user")?.content?.replace(/\n\nAttached:[\s\S]*/,"").trim();return first ? `${first.slice(0,58)}${first.length>58?"…":""}` : "New investigation";}
function chatThread(id=state.chat.activeId){return state.chat.threads.find(thread=>thread.id===id);}
function saveChatThreads(){
  const safe=state.chat.threads.map(({id,title,createdAt,updatedAt,messages})=>({id,title,createdAt,updatedAt,messages:messages.map(({role,content})=>({role,content}))}));
  localStorage.setItem(CHAT_STORAGE_KEY,JSON.stringify(safe));
}
function loadChatThreads(){
  try{
    const stored=JSON.parse(localStorage.getItem(CHAT_STORAGE_KEY)||"[]");
    state.chat.threads=Array.isArray(stored)?stored.filter(thread=>thread&&typeof thread.id==="string"&&Array.isArray(thread.messages)).map(thread=>({id:thread.id,title:String(thread.title||chatTitle(thread.messages)),createdAt:thread.createdAt||new Date().toISOString(),updatedAt:thread.updatedAt||thread.createdAt||new Date().toISOString(),messages:thread.messages.filter(message=>["user","assistant"].includes(message.role)&&typeof message.content==="string").slice(-80)})):[];
  }catch{state.chat.threads=[];}
  state.chat.threads.sort((a,b)=>new Date(b.updatedAt)-new Date(a.updatedAt));
  if(state.chat.threads.length) selectChatThread(state.chat.threads[0].id,{focus:false}); else newChatThread({focus:false});
}
function renderChatThreads(query=$("#chatThreadSearch")?.value||""){
  const list=$("#chatThreadList"); if(!list)return;
  const q=query.trim().toLowerCase();
  const matches=state.chat.threads.filter(thread=>!q||thread.title.toLowerCase().includes(q)||thread.messages.some(message=>message.content.toLowerCase().includes(q)));
  list.innerHTML=matches.length?matches.map(thread=>`<article class="chat-thread ${thread.id===state.chat.activeId?"active":""}" data-chat-thread="${escapeHtml(thread.id)}" tabindex="0"><div><b>${escapeHtml(thread.title)}</b><time>${escapeHtml(formatTime(thread.updatedAt))}</time></div><small>${escapeHtml(thread.messages.at(-1)?.content?.replace(/\s+/g," ").slice(0,72)||"No messages yet")}</small></article>`).join(""):`<div class="chat-thread-empty">No local conversations match this search.</div>`;
}
function renderChatTranscript(){
  const box=$("#chatMessages"); if(!box)return;
  const thread=chatThread(); const messages=thread?.messages||[];
  $("#chatThreadTitle").textContent=thread?.title||"New investigation";
  $("#chatContextLine").textContent=messages.length?"Context: endpoint overview · recent alerts · selected attachments":"Context: ready for a new endpoint investigation";
  box.innerHTML="";
  if(!messages.length){box.innerHTML=`<article class="chat-message assistant"><b>THRYVE REVIEW</b><p>Start a focused investigation. I can relate your question to the local endpoint overview, recent alerts, events, and enabled rules.</p></article>`;return;}
  messages.forEach(message=>appendChatMessage(message.role,message.content));
}
function selectChatThread(id,{focus=true}={}){
  const thread=chatThread(id);if(!thread)return;
  state.chat.activeId=id;state.chat.messages=thread.messages;state.chat.attachments=[];renderChatAttachments();renderChatThreads();renderChatTranscript();
  if(focus) $("#chatPrompt")?.focus();
}
function newChatThread({focus=true}={}){
  const now=new Date().toISOString();const thread={id:chatId(),title:"New investigation",createdAt:now,updatedAt:now,messages:[]};
  state.chat.threads.unshift(thread);state.chat.activeId=thread.id;state.chat.messages=thread.messages;saveChatThreads();renderChatThreads();renderChatTranscript();if(focus)$("#chatPrompt")?.focus();
}
function persistActiveChat(){
  const thread=chatThread();if(!thread)return;thread.messages=state.chat.messages;thread.title=chatTitle(thread.messages);thread.updatedAt=new Date().toISOString();
  state.chat.threads.sort((a,b)=>new Date(b.updatedAt)-new Date(a.updatedAt));saveChatThreads();renderChatThreads();$("#chatThreadTitle").textContent=thread.title;
}
function renameActiveChat(){const thread=chatThread();if(!thread)return;const title=window.prompt("Conversation title",thread.title);if(title===null)return;thread.title=title.trim().slice(0,80)||"Untitled investigation";thread.updatedAt=new Date().toISOString();saveChatThreads();renderChatThreads();renderChatTranscript();}
function deleteActiveChat(){const thread=chatThread();if(!thread||!window.confirm(`Delete “${thread.title}”? This only removes local browser history.`))return;state.chat.threads=state.chat.threads.filter(item=>item.id!==thread.id);saveChatThreads();if(state.chat.threads.length)selectChatThread(state.chat.threads[0].id,{focus:false});else newChatThread({focus:false});}
function chatAttachmentSize(bytes){return bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : `${Math.ceil(bytes / 1024)} KB`;}
function renderChatAttachments(){
  const box=$("#chatAttachments");
  if(!box)return;
  box.innerHTML=state.chat.attachments.map((file,index)=>`<span class="chat-attachment"><b>${escapeHtml(file.name)}</b><small>${escapeHtml(chatAttachmentSize(file.size))}</small><button type="button" data-chat-remove="${index}" aria-label="Remove ${escapeHtml(file.name)}">×</button></span>`).join("");
}
function appendChatMessage(role,content,{pending=false}={}){
  const box=$("#chatMessages");if(!box)return null;
  const item=document.createElement("article");item.className=`chat-message ${role}${pending?" pending":""}`;
  const label=role==="user"?"ANALYST":"THRYVE REVIEW";
  item.innerHTML=`<b>${label}</b><p>${escapeHtml(cleanExternalAnalysis(content)).replace(/\n/g,"<br>")}</p>`;
  box.append(item);box.scrollTop=box.scrollHeight;return item;
}
async function queueChatAttachments(files){
  const selected=[...files];
  if(selected.length+state.chat.attachments.length>4){toast("Attachment limit reached","Attach up to four files per request","error");return;}
  const total=state.chat.attachments.reduce((sum,file)=>sum+file.size,0)+selected.reduce((sum,file)=>sum+file.size,0);
  if(total>6*1024*1024){toast("Attachments are too large","The combined limit is 6 MB","error");return;}
  try{
    const prepared=await Promise.all(selected.map(file=>new Promise((resolve,reject)=>{
      const reader=new FileReader();reader.onload=()=>resolve({name:file.name,mime:file.type||"application/octet-stream",data:String(reader.result).split(",")[1]||"",size:file.size});reader.onerror=()=>reject(new Error(`Could not read ${file.name}`));reader.readAsDataURL(file);
    })));
    state.chat.attachments.push(...prepared);renderChatAttachments();
  }catch(error){toast("Attachment could not be read",error.message,"error");}
}
async function sendAnalystChat(event){
  event.preventDefault();const input=$("#chatPrompt"),button=$("#chatSend");
  const prompt=input.value.trim()|| (state.chat.attachments.length?"Review the selected attachment(s) in the context of this endpoint and identify the safest next validation steps.":"");
  if(!prompt){toast("Enter a question","Add a question or attach evidence for review","error");return;}
  const attachments=[...state.chat.attachments];const attachmentNote=attachments.length?`\n\nAttached: ${attachments.map(file=>file.name).join(", ")}`:"";
  const userMessage={role:"user",content:`${prompt}${attachmentNote}`};state.chat.messages.push(userMessage);persistActiveChat();appendChatMessage("user",userMessage.content);
  input.value="";state.chat.attachments=[];renderChatAttachments();$("#chatFiles").value="";button.disabled=true;button.textContent="Reviewing…";
  const pending=appendChatMessage("assistant","Reviewing the bounded endpoint context and selected evidence…",{pending:true});
  try{
    const payload=await request(API.chat,{method:"POST",timeout:90000,body:JSON.stringify({prompt,history:state.chat.messages.slice(0,-1).slice(-8),attachments})});
    const answer=cleanExternalAnalysis(payload.analysis||"No analysis was returned.");pending.remove();state.chat.messages.push({role:"assistant",content:answer});persistActiveChat();appendChatMessage("assistant",answer);
  }catch(error){pending.remove();const answer=`Review unavailable: ${error.message}`;state.chat.messages.push({role:"assistant",content:answer});persistActiveChat();appendChatMessage("assistant",answer);toast("Gemini review unavailable",error.message,"error");}
  finally{button.disabled=false;button.textContent="Send to Gemini";}
}
async function analyzeStoryWithGemini(item){
  const button=$("#aiAnalyzeStory"), status=$("#aiStoryStatus"), result=$("#aiStoryResult");
  button.disabled=true; status.textContent="Gemini is analyzing the selected evidence…"; result.classList.remove("hidden"); result.textContent="Loading defensive assessment…";
  try{const payload=await request("/api/ai/analyze",{method:"POST",timeout:60000,body:JSON.stringify({prompt:"Explain this alert for an OWASP Amman SOC demo and prioritize safe defensive validation.",evidence:item})}); result.innerHTML=`<h3>External evidence review</h3><pre>${escapeHtml(cleanExternalAnalysis(payload.analysis||"No analysis returned."))}</pre>`; status.textContent=`Model: ${payload.model||"Gemini"}`;}
  catch(error){result.innerHTML=`<b>Gemini unavailable</b><p>${escapeHtml(error.message)}</p>`;status.textContent="Configure GEMINI_API_KEY in the local process environment.";}
  finally{button.disabled=false;}
}

function renderCoverage(data,sources) {
  const latestSources = [];
  const seen = new Set();
  for (const source of sources) {
    const sourceName = pick(source,["name","source","label","type","collector"]);
    if (!seen.has(sourceName)) { seen.add(sourceName); latestSources.push(source); }
  }
  sources = latestSources;
  let coverage = number(pick(data,["coverage_score","coverage_percent"],0));
  if (!coverage && sources.length) coverage = Math.round(100 * sources.filter(s => /complete|active|healthy|true/i.test(String(pick(s,["status","healthy","enabled","active"],false)))).length / sources.length);
  setText("coverageScore",coverage); setText("coverageStatus",coverage >= 85 ? "Good coverage" : coverage ? "Partial coverage" : "No data");
  const list = $("#sourceList");
  if (!sources.length) { list.innerHTML = `<div class="empty-state small"><b>No source status</b><p>Run a full collection to refresh coverage.</p></div>`; return; }
  list.innerHTML = sources.slice(0,6).map(source => {
    const name = pick(source,["name","source","label","type","collector"]); const enabled = /complete|active|healthy|true/i.test(String(pick(source,["status","healthy","enabled","active"],false)));
    const percent = Math.max(0,Math.min(100,number(pick(source,["coverage","percent"],enabled ? 100 : 0))));
    return `<div class="source-item"><div><span>${escapeHtml(name)}</span><b style="color:${enabled ? "var(--mint)" : "var(--red)"}">${enabled ? "ACTIVE" : "OFFLINE"}</b></div><div class="meter"><i style="width:${percent}%"></i></div></div>`;
  }).join("");
}

function renderSpark(values) {
  const valid = values.length ? values.slice(-18) : [];
  const max = Math.max(...valid,1); $("#sparkBars").innerHTML = valid.length ? valid.map(v => `<i class="${v/max > .75 ? "hot" : ""}" style="height:${Math.max(5,Math.round(v/max*100))}%"></i>`).join("") : `<span class="muted">No telemetry yet</span>`;
}
function drawEventChart(values) {
  const canvas = $("#eventChart"); if (!canvas) return;
  const rect = canvas.getBoundingClientRect(); const ratio = window.devicePixelRatio || 1; canvas.width = Math.max(300,rect.width)*ratio; canvas.height = 190*ratio;
  const ctx = canvas.getContext("2d"); ctx.scale(ratio,ratio); const w = canvas.width/ratio,h=190; ctx.clearRect(0,0,w,h);
  ctx.strokeStyle="#24333b"; ctx.lineWidth=1; for(let y=25;y<h;y+=40){ctx.beginPath();ctx.moveTo(0,y+.5);ctx.lineTo(w,y+.5);ctx.stroke();}
  if (!values.length) { ctx.fillStyle="#637781"; ctx.font="11px Tahoma"; ctx.textAlign="center"; ctx.fillText("No event volume data",w/2,h/2); return; }
  const data=values.slice(-40), max=Math.max(...data,1), x=i=>data.length===1?w/2:i*(w/(data.length-1)), y=v=>h-18-(v/max)*(h-42);
  ctx.beginPath(); data.forEach((v,i)=>i?ctx.lineTo(x(i),y(v)):ctx.moveTo(x(i),y(v))); ctx.strokeStyle="#40c7d5";ctx.lineWidth=1.5;ctx.stroke();
  ctx.lineTo(x(data.length-1),h);ctx.lineTo(0,h);ctx.closePath();ctx.fillStyle="rgba(64,199,213,.07)";ctx.fill();
  data.forEach((v,i)=>{if(i%Math.max(1,Math.floor(data.length/9))===0||i===data.length-1){ctx.fillStyle="#40c7d5";ctx.fillRect(x(i)-1.5,y(v)-1.5,3,3);}});
}

function buildDataView(type) {
  const config=viewConfig[type], view=$(`#view-${type}`); if (!view || view.dataset.built) return;
  view.dataset.built="true";
  view.innerHTML=`<div class="view-heading"><div><span class="section-code">${config.code}</span><h1>${config.title}</h1><p>${config.subtitle}</p></div><button class="secondary-button" type="button" data-refresh-view="${type}">↻ Refresh</button></div>
    <div class="data-toolbar"><label class="filter-search"><input type="search" data-search="${type}" placeholder="Search ${config.title.toLowerCase()}…" aria-label="Search ${config.title}"></label><select data-filter="${type}" aria-label="Filter ${config.title}">${config.filters.map(([v,l])=>`<option value="${escapeHtml(v)}">${escapeHtml(l)}</option>`).join("")}</select><span class="data-counter" id="count-${type}">— RECORDS</span></div>
    <section class="data-panel"><div class="table-wrap"><table><thead><tr>${config.columns.map(c=>`<th>${c[1]}</th>`).join("")}<th aria-label="Action"></th></tr></thead><tbody id="body-${type}"><tr><td colspan="${config.columns.length+1}"><div class="loading-row"><i></i> Loading ${config.title.toLowerCase()}…</div></td></tr></tbody></table></div><div class="pagination" id="pager-${type}"></div></section>`;
  state.tables[type]={raw:[],filtered:[],page:1,search:"",filter:""};
}

async function loadDataView(type,{force=false}={}) {
  buildDataView(type); const table=state.tables[type];
  if (table.raw.length && !force) { renderDataView(type); return; }
  const body=$(`#body-${type}`); body.innerHTML=`<tr><td colspan="${viewConfig[type].columns.length+1}"><div class="loading-row"><i></i> Loading…</div></td></tr>`;
  try {
    const payload=await request(API[type]); const raw=asArray(payload,[type]); table.raw=raw.map(item=>normalizeItem(type,item)); table.page=1; renderDataView(type);
  } catch(error) { body.innerHTML=`<tr><td colspan="${viewConfig[type].columns.length+1}"><div class="empty-state error-state"><span>!</span><b>Could not load ${viewConfig[type].title.toLowerCase()}</b><p>${escapeHtml(error.message)}</p><button data-refresh-view="${type}">Retry</button></div></td></tr>`; setText(`count-${type}`,"ERROR"); }
}

function renderDataView(type) {
  const config=viewConfig[type], table=state.tables[type], q=table.search.trim().toLowerCase(), f=table.filter.toLowerCase();
  table.filtered=table.raw.filter(item=>{
    const matchesSearch=!q || Object.values(item).some(v=>String(v??"").toLowerCase().includes(q));
    let fv=String(item[config.filterKey]??"").toLowerCase(); if(config.filterKey==="severity") fv=normalizedSeverity(fv); if(config.filterKey==="enabled") fv=String(Boolean(item[config.filterKey]));
    return matchesSearch && (!f || fv.includes(f));
  });
  const pages=Math.max(1,Math.ceil(table.filtered.length/state.pageSize)); table.page=Math.min(table.page,pages); const start=(table.page-1)*state.pageSize; const items=table.filtered.slice(start,start+state.pageSize); const body=$(`#body-${type}`);
  setText(`count-${type}`,`${table.filtered.length} RECORDS`);
  if(!items.length){body.innerHTML=`<tr><td colspan="${config.columns.length+1}"><div class="empty-state"><span>⌁</span><b>${table.raw.length ? "No matching results" : "No data yet"}</b><p>${table.raw.length ? "Change the search query or filter." : "Run the relevant collector, then refresh this view."}</p></div></td></tr>`;}
  else body.innerHTML=items.map((item,index)=>{const id=`${type}-${start+index}`;state.cache[id]=item;return `<tr data-row="${id}" tabindex="0">${config.columns.map(([key,,renderer])=>`<td>${renderer(item[key])}</td>`).join("")}<td><button class="row-action" data-open-row="${id}" aria-label="View details">…</button></td></tr>`;}).join("");
  renderPagination(type,pages,start,items.length);
}
function renderPagination(type,pages,start,count) {
  const t=state.tables[type], pager=$(`#pager-${type}`); if(!pager)return;
  const begin=count?start+1:0,end=start+count;
  const around=[];for(let p=Math.max(1,t.page-2);p<=Math.min(pages,t.page+2);p++)around.push(p);
  pager.innerHTML=`<span>Showing ${begin}–${end} of ${t.filtered.length}</span><div><button data-page="${type}:prev" ${t.page<=1?"disabled":""}>‹</button>${around.map(p=>`<button class="${p===t.page?"active":""}" data-page="${type}:${p}">${p}</button>`).join("")}<button data-page="${type}:next" ${t.page>=pages?"disabled":""}>›</button></div>`;
}

function navigate(view,{replace=false,fromRoute=false}={}) {
  if (!document.getElementById(`view-${view}`)) return; state.activeView=view;
  $$(".view").forEach(el=>el.classList.toggle("active",el.id===`view-${view}`)); $$(".nav-item").forEach(el=>el.classList.toggle("active",el.dataset.view===view));
  const target=$(`#view-${view}`); setText("viewCrumb",target.dataset.title); document.title=`${target.dataset.title} | Thryve`; closeMobileNav(); window.scrollTo({top:0,behavior:"smooth"});
  if(!fromRoute){const url=view==="overview"?"/":`/${view}`; if(replace)history.replaceState({view},"",url); else history.pushState({view},"",url);}
  if(viewConfig[view]) loadDataView(view); if(view==="investigations") loadCases();
}

function viewFromPath(){const value=location.pathname.replace(/^\/+|\/+$/g,"");return document.getElementById(`view-${value}`)?value:"overview";}

function openDetails(id) {
  const item=state.cache[id]; if(!item)return; state.selectedRecord=item;
  state.selectedRecordType=id.split("-")[0];
  setText("drawerType",state.selectedRecordType.toUpperCase()); setText("drawerTitle",maskDisplay(pick(item,["title","name","message","description"],"Record details")));
  const priority=["severity","status","timestamp","source","mitre","event_id","pid","process","remote_address"];
  const fields=priority.filter(k=>item[k]!==undefined).map(k=>`<div class="detail-field"><span>${escapeHtml(k.replaceAll("_"," ").toUpperCase())}</span><b class="${/time|id|pid|address|mitre/.test(k)?"mono":""}">${escapeHtml(maskDisplay(item[k],/host|computer/.test(k)?"host":"generic"))}</b></div>`).join("");
  const actions=state.selectedRecordType==="alerts"&&item.id?`<h3 class="drawer-section-title">TRIAGE ACTIONS</h3><div class="case-actions"><button type="button" data-alert-state="investigating">Start investigation</button><button type="button" data-alert-state="closed">Close alert</button><button type="button" data-alert-state="false_positive">False positive</button></div>`:state.selectedRecordType==="rules"&&item.id?`<h3 class="drawer-section-title">RULE CONTROL</h3><button class="secondary-button" type="button" data-toggle-rule="${escapeHtml(item.id)}">${item.enabled?"Disable rule":"Enable rule"}</button>`:"";
  $("#drawerContent").innerHTML=`<div class="detail-grid">${fields||`<div class="detail-field"><span>RECORD</span><b>Local telemetry record</b></div>`}</div>${item.mitre&&item.mitre!=="—"?`<h3 class="drawer-section-title">MITRE ATT&CK MAPPING</h3><div class="detail-field"><span>TECHNIQUE</span><b class="mono">${escapeHtml(item.mitre)}</b></div>`:""}${actions}<h3 class="drawer-section-title">RAW JSON ${state.privacyMode?"· MASKED FOR PRESENTATION":""}</h3><pre class="raw-block">${escapeHtml(JSON.stringify(redactedClone(item),null,2))}</pre>`;
  $("#detailDrawer").classList.add("open");$("#drawerScrim").classList.add("open");$("#detailDrawer").setAttribute("aria-hidden","false");$("#drawerClose").focus();
}
function closeDetails(){$("#detailDrawer").classList.remove("open");$("#drawerScrim").classList.remove("open");$("#detailDrawer").setAttribute("aria-hidden","true");}

async function collect(type,button) {
  const targets=$$(`[data-collection="${CSS.escape(type)}"]`); targets.forEach(el=>{el.disabled=true;el.classList.add("busy");});
  const original=button?.querySelector("b")?.textContent; if(button?.querySelector("b"))button.querySelector("b").textContent="Collecting…";
  const collector = ({full:"all",events:"windows_events"})[type] || type;
  try { const result=await request(API.collect,{method:"POST",body:JSON.stringify({collector}),timeout:120000}); const total=(result.results||[]).reduce((sum,x)=>sum+number(x.inserted),0);toast("Collection complete",`${fmt(total)} records inserted · ${fmt(result.new_alerts)} new alerts`,"success"); state.tables[type]&&(state.tables[type].raw=[]); await loadCore({quiet:true}); if(viewConfig[state.activeView])await loadDataView(state.activeView,{force:true}); }
  catch(error){toast("Collection failed",error.message,"error");}
  finally {targets.forEach(el=>{el.disabled=false;el.classList.remove("busy");});if(button?.querySelector("b")&&original)button.querySelector("b").textContent=original;}
}

async function searchIOC(query) {
  const box=$("#iocResults"); box.innerHTML=`<div class="loading-row"><i></i> Searching local telemetry…</div>`;
  try {const payload=await request(`${API.search}?q=${encodeURIComponent(query)}`);const results=asArray(payload,["matches","results"]).concat(asArray(payload,["events"]),asArray(payload,["alerts"]));if(!results.length){box.innerHTML=`<div class="empty-state small"><span>∅</span><b>No matches</b><p>The indicator does not appear in available telemetry.</p></div>`;return;}box.innerHTML=results.slice(0,100).map((r,i)=>{const item={...(r.data||{}),...r};const id=`search-${i}`;state.cache[id]=item;return `<button class="result-item" data-open-row="${id}" type="button"><span>${escapeHtml(pick(item,["event_type","type","source","category"],"MATCH"))}</span><b>${escapeHtml(maskDisplay(pick(item,["title","value","message","name"])))}</b><small>${escapeHtml(formatTime(pick(item,["timestamp","time","created_at"])))}</small></button>`;}).join("");}
  catch(error){box.innerHTML=`<div class="empty-state error-state small"><span>!</span><b>Search failed</b><p>${escapeHtml(error.message)}</p></div>`;}
}

async function loadCases() {
  const box=$("#caseList");
  try {const payload=await request(API.cases);const cases=asArray(payload,["cases"]);if(!cases.length){box.innerHTML=`<div class="empty-state small"><span>＋</span><b>No cases</b><p>Create a case to link evidence and analyst notes.</p></div>`;return;}box.innerHTML=cases.map((c,i)=>{const id=pick(c,["id","case_id","uuid"],i);state.cache[`case-${id}`]=c;return `<article class="case-item ${state.selectedCase&&String(pick(state.selectedCase,["id","case_id","uuid"]))===String(id)?"active":""}" data-case="${escapeHtml(id)}" tabindex="0"><h3>${escapeHtml(maskDisplay(pick(c,["name","title"],`Case ${id}`)))}</h3><time>${escapeHtml(formatTime(pick(c,["updated_at","created_at","timestamp"])))}</time><p>${escapeHtml(maskDisplay(pick(c,["description","summary"],"No description")))}</p><div class="case-actions"><button type="button" data-select-case="${escapeHtml(id)}">Open case</button><button type="button" data-report-case="${escapeHtml(id)}">PDF report</button><button type="button" data-export-case="${escapeHtml(id)}">Export package</button></div></article>`;}).join("");}
  catch(error){box.innerHTML=`<div class="empty-state error-state small"><span>!</span><b>Could not load cases</b><p>${escapeHtml(error.message)}</p></div>`;}
}
async function selectCase(id){let c=state.cache[`case-${id}`];if(!c)return;try{c=await request(`${API.cases}/${encodeURIComponent(id)}`);state.cache[`case-${id}`]=c;}catch(error){toast("Could not open case",error.message,"error");return;}state.selectedCase=c;$$('.case-item').forEach(el=>el.classList.toggle('active',el.dataset.case===String(id)));$("#caseNotes").disabled=false;$("#saveNotes").disabled=false;$("#caseNotes").value="";setText("notesState",`Add a note to ${maskDisplay(pick(c,["name","title","id"],id))}`);const timeline=asArray(c,["timeline","evidence","items"]);$("#evidenceTimeline").innerHTML=timeline.length?timeline.slice().reverse().map(x=>`<li><time>${escapeHtml(formatFullTime(pick(x,["timestamp","time","created_at"])))}</time><b>${escapeHtml(pick(x,["title","item_type","type","name"],"Evidence"))}</b><p>${escapeHtml(maskDisplay(pick(x,["note","description","summary","value"],"")))}</p></li>`).join(""):`<li class="empty-timeline">No evidence has been linked to this case yet.</li>`;}
async function createCase(){const name=$("#caseName").value.trim();if(!name)return;const button=$("#createCaseSubmit");button.disabled=true;try{const created=await request(API.cases,{method:"POST",body:JSON.stringify({name,title:name,description:$("#caseDescription").value.trim()})});$("#caseDialog").close();$("#caseForm").reset();toast("Case created",pick(created,["name","title","message"],name),"success");await loadCases();}catch(error){toast("Could not create case",error.message,"error");}finally{button.disabled=false;}}
async function saveNotes(){if(!state.selectedCase)return;const id=pick(state.selectedCase,["id","case_id","uuid"],"");const note=$("#caseNotes").value.trim();if(!note)return;const button=$("#saveNotes");button.disabled=true;try{await request(`${API.cases}/${encodeURIComponent(id)}/items`,{method:"POST",body:JSON.stringify({item_type:"note",note})});$("#caseNotes").value="";toast("Note saved","Added to the case timeline","success");await selectCase(id);}catch(error){toast("Could not save note",error.message,"error");}finally{button.disabled=false;}}
function exportCase(id){const url=`${API.export}?case_id=${encodeURIComponent(id)}`;window.location.assign(url);toast("Export started","The local engine is building the case package");}
function downloadReport(caseId){const suffix=caseId?`?case_id=${encodeURIComponent(caseId)}`:"";window.location.assign(`${API.report}${suffix}`);toast("Report requested","The local engine is preparing the PDF evidence report","success");}

async function addSelectedToCase(){
  if(!state.selectedRecord)return;
  if(!state.selectedCase){closeDetails();navigate("investigations");toast("Select a case first","Open a case, then return to the record you want to link");return;}
  const caseId=pick(state.selectedCase,["id","case_id","uuid"],"");
  const recordType=state.selectedRecordType==="alerts"?"alert":state.selectedRecordType==="search"?(state.selectedRecord.rule_id?"alert":"event"):"event";
  const itemId=pick(state.selectedRecord,["id","event_id"],null);
  if(!itemId){toast("This record cannot be linked","The engine did not return a stable record ID","error");return;}
  const button=$("#addToCase");button.disabled=true;
  try{await request(`${API.cases}/${encodeURIComponent(caseId)}/items`,{method:"POST",body:JSON.stringify({item_type:recordType,item_id:itemId,note:"Added from the triage console"})});toast("Evidence linked to case",`${recordType} #${itemId}`,"success");closeDetails();}
  catch(error){toast("Could not link evidence",error.message,"error");}finally{button.disabled=false;}
}
async function changeAlertState(status){
  const id=state.selectedRecord?.id;if(!id)return;
  try{await request(`${API.alerts}/${encodeURIComponent(id)}/status`,{method:"POST",body:JSON.stringify({status})});state.selectedRecord.status=status;toast("Alert status updated",status,"success");closeDetails();state.tables.alerts&&(state.tables.alerts.raw=[]);await loadDataView("alerts",{force:true});await loadCore({quiet:true});}
  catch(error){toast("Could not update alert",error.message,"error");}
}
async function toggleRule(id){
  const enabled=!Boolean(state.selectedRecord?.enabled);
  try{await request(`${API.rules}/${encodeURIComponent(id)}/toggle`,{method:"POST",body:JSON.stringify({enabled})});toast(enabled?"Rule enabled":"Rule disabled",id,"success");closeDetails();state.tables.rules.raw=[];await loadDataView("rules",{force:true});}
  catch(error){toast("Could not update rule",error.message,"error");}
}

function openCaseDialog(){if(typeof $("#caseDialog").showModal==="function"){$("#caseDialog").showModal();setTimeout(()=>$("#caseName").focus(),50);}}
function openPalette(){const p=$("#commandPalette");p.classList.add("open");p.setAttribute("aria-hidden","false");$("#commandInput").value="";setTimeout(()=>$("#commandInput").focus(),20);}
function closePalette(){const p=$("#commandPalette");p.classList.remove("open");p.setAttribute("aria-hidden","true");}
function openMobileNav(){$("#sidebar").classList.add("open");$("#scrim").classList.add("open");}
function closeMobileNav(){$("#sidebar").classList.remove("open");$("#scrim").classList.remove("open");}
function configureRefresh(){clearInterval(state.refreshTimer);if(state.refreshSeconds>0)state.refreshTimer=setInterval(()=>{if(document.visibilityState==="visible")loadCore({quiet:true});},state.refreshSeconds*1000);}

function applyPrivacyState({announce=false}={}){
  document.body.classList.toggle("privacy-active",state.privacyMode);
  $("#demoBadge").classList.toggle("hidden",!state.privacyMode);
  $("#privacyToggle").setAttribute("aria-pressed",String(state.privacyMode));
  $("#privacyToggle small").textContent=state.privacyMode?"ON":"OFF";
  localStorage.setItem("aegis_privacy_mode",String(state.privacyMode));
  if(Object.keys(state.status).length)renderStatus(state.status);
  if(Object.keys(state.overview).length)renderOverview(state.overview);
  Object.keys(state.tables).forEach(type=>state.tables[type].raw.length&&renderDataView(type));
  if(state.activeView==="investigations")loadCases();
  if(announce)toast(state.privacyMode?"Privacy Shield enabled":"Privacy Shield disabled",state.privacyMode?"Hostnames, users, local paths, and IPs are masked in the UI.":"Original evidence values are visible again.",state.privacyMode?"success":"");
}

function bindEvents() {
  document.addEventListener("click",event=>{
    const nav=event.target.closest("[data-view],[data-go]");if(nav){navigate(nav.dataset.view||nav.dataset.go);return;}
    const collectButton=event.target.closest("[data-collection]");if(collectButton){collect(collectButton.dataset.collection,collectButton);return;}
    const refresh=event.target.closest("[data-refresh-view]");if(refresh){loadDataView(refresh.dataset.refreshView,{force:true});return;}
    const row=event.target.closest("[data-open-row],tr[data-row]");if(row){openDetails(row.dataset.openRow||row.dataset.row);return;}
    const page=event.target.closest("[data-page]");if(page){const[type,action]=page.dataset.page.split(":");const t=state.tables[type];t.page=action==="prev"?t.page-1:action==="next"?t.page+1:Number(action);renderDataView(type);return;}
    const select=event.target.closest("[data-select-case]");if(select){selectCase(select.dataset.selectCase);return;}
    const exp=event.target.closest("[data-export-case]");if(exp){exportCase(exp.dataset.exportCase);return;}const report=event.target.closest("[data-report-case]");if(report){downloadReport(report.dataset.reportCase);return;}
    const alertState=event.target.closest("[data-alert-state]");if(alertState){changeAlertState(alertState.dataset.alertState);return;}
    const ruleToggle=event.target.closest("[data-toggle-rule]");if(ruleToggle){toggleRule(ruleToggle.dataset.toggleRule);return;}
    const cmd=event.target.closest("[data-command-view]");if(cmd){const v=cmd.dataset.commandView;closePalette();navigate(v);if(v==="investigations")setTimeout(()=>$("#iocInput").focus(),100);}
  });
  document.addEventListener("input",event=>{if(event.target.matches("[data-search]")){const t=state.tables[event.target.dataset.search];t.search=event.target.value;t.page=1;renderDataView(event.target.dataset.search);}});
  document.addEventListener("change",event=>{if(event.target.matches("[data-filter]")){const t=state.tables[event.target.dataset.filter];t.filter=event.target.value;t.page=1;renderDataView(event.target.dataset.filter);}});
  $("#storyAlertSelect").addEventListener("change",event=>renderStoryline(state.storyAlerts,Number(event.target.value)));
  document.addEventListener("keydown",event=>{
    if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==="k"){event.preventDefault();openPalette();}
    if(event.key==="Escape"){closePalette();closeDetails();closeMobileNav();}
    if(event.key==="Enter"&&event.target.matches("tr[data-row]"))openDetails(event.target.dataset.row);
  });
  $("#menuButton").addEventListener("click",openMobileNav);$("#navClose").addEventListener("click",closeMobileNav);$("#scrim").addEventListener("click",closeMobileNav);
  $("#drawerClose").addEventListener("click",closeDetails);$("#drawerScrim").addEventListener("click",closeDetails);
  $("#globalSearchButton").addEventListener("click",openPalette);$("#commandPalette").addEventListener("click",e=>{if(e.target===$("#commandPalette"))closePalette();});
  $("#privacyToggle").addEventListener("click",()=>{state.privacyMode=!state.privacyMode;closeDetails();applyPrivacyState({announce:true});});
  $("#runMemory").addEventListener("click",runMemoryAnalysis); loadMemoryStatus();
  $("#chatForm").addEventListener("submit",sendAnalystChat);$("#chatFiles").addEventListener("change",event=>{queueChatAttachments(event.target.files);event.target.value="";});$("#chatAttachments").addEventListener("click",event=>{const button=event.target.closest("[data-chat-remove]");if(!button)return;state.chat.attachments.splice(Number(button.dataset.chatRemove),1);renderChatAttachments();});
  $("#newChat").addEventListener("click",()=>newChatThread());$("#renameChat").addEventListener("click",renameActiveChat);$("#deleteChat").addEventListener("click",deleteActiveChat);
  $("#chatThreadSearch").addEventListener("input",event=>renderChatThreads(event.target.value));$("#chatThreadList").addEventListener("click",event=>{const item=event.target.closest("[data-chat-thread]");if(item)selectChatThread(item.dataset.chatThread);});$("#chatThreadList").addEventListener("keydown",event=>{if(event.key==="Enter"||event.key===" "){const item=event.target.closest("[data-chat-thread]");if(item){event.preventDefault();selectChatThread(item.dataset.chatThread);}}});
  $("#runArtifactTriage").addEventListener("click",runArtifactTriage); loadForensicTools();
  $("#downloadReport").addEventListener("click",()=>downloadReport());
  $("#runYaraScan").addEventListener("click",runYaraScan);
  $("#retryButton").addEventListener("click",()=>loadCore());$("#quickCase").addEventListener("click",openCaseDialog);$("#newCase").addEventListener("click",openCaseDialog);
  $("#caseForm").addEventListener("submit",e=>{e.preventDefault();createCase();});$("#refreshCases").addEventListener("click",loadCases);$("#saveNotes").addEventListener("click",saveNotes);
  $("#iocForm").addEventListener("submit",e=>{e.preventDefault();const q=$("#iocInput").value.trim();if(q)searchIOC(q);});
  $("#copyJson").addEventListener("click",async()=>{if(!state.selectedRecord)return;try{await navigator.clipboard.writeText(JSON.stringify(state.selectedRecord,null,2));toast("JSON copied","The original record is in your clipboard","success");}catch{toast("Copy failed","Copy the JSON manually from the record panel","error");}});
  $("#addToCase").addEventListener("click",addSelectedToCase);
  $("#rowLimit").value=String(state.pageSize);$("#rowLimit").addEventListener("change",e=>{state.pageSize=Number(e.target.value);localStorage.setItem("aegis_page_size",state.pageSize);Object.keys(state.tables).forEach(t=>{state.tables[t].page=1;renderDataView(t);});});
  $("#autoRefresh").value=String(state.refreshSeconds);$("#autoRefresh").addEventListener("change",e=>{state.refreshSeconds=Number(e.target.value);localStorage.setItem("aegis_refresh",state.refreshSeconds);configureRefresh();toast("Refresh interval updated",state.refreshSeconds?`Every ${state.refreshSeconds} seconds`:"Auto refresh is off");});
  $("#purgeViewCache").addEventListener("click",()=>{for(const t of Object.values(state.tables)){t.raw=[];t.filtered=[];t.page=1;}state.cache={};toast("View cache cleared","No evidence was deleted from the engine","success");});
  window.addEventListener("resize",()=>drawEventChart(asArray(state.overview,["event_volume","volume","timeline"]).map(v=>typeof v==="number"?v:number(pick(v,["count","value","events"],0)))));
}

async function loadMemoryStatus(){try{const s=await request("/api/memory/status");setText("memoryAvailability",s.available?"Volatility 3 available":"Install Volatility 3 to enable");}catch(e){setText("memoryAvailability","Memory service unavailable");}}
async function runMemoryAnalysis(){const path=$("#memoryImagePath").value.trim(), plugin=$("#memoryPlugin").value, out=$("#memoryOutput"), button=$("#runMemory");if(!path){out.textContent="Enter a local memory image path first.";return;}button.disabled=true;out.textContent="Running bounded Volatility analysis…";try{const r=await request("/api/memory/analyze",{method:"POST",timeout:200000,body:JSON.stringify({image_path:path,plugin})});out.textContent=JSON.stringify(r.result,null,2);}catch(e){out.textContent=`Memory analysis failed: ${e.message}`;}finally{button.disabled=false;}}
async function loadForensicTools(){const box=$("#forensicTools");try{const payload=await request("/api/forensics/tools");box.innerHTML=(payload.items||[]).map(tool=>{const state=tool.available?"READY":tool.integration==="external"?"EXTERNAL":"OPTIONAL";return `<div class="tool-item"><div><b>${escapeHtml(tool.name)}</b><small>${escapeHtml(tool.area)} · ${escapeHtml(tool.capability)}</small></div><span class="severity ${tool.available?"healthy":"info"}">${state}</span></div>`}).join("");}catch(e){box.textContent="Could not read the local toolchain.";}}
async function runArtifactTriage(){const path=$("#artifactPath").value.trim(),out=$("#artifactOutput"),button=$("#runArtifactTriage");if(!path){out.textContent="Enter a local artifact path first.";return;}button.disabled=true;out.textContent="Computing hash and parsing artifact…";try{const r=await request("/api/forensics/file-triage",{method:"POST",timeout:200000,body:JSON.stringify({path})});out.textContent=JSON.stringify(r.result,null,2);}catch(e){out.textContent=`Artifact triage failed: ${e.message}`;}finally{button.disabled=false;}}
async function runYaraScan(){const path=$("#artifactPath").value.trim(),out=$("#artifactOutput"),button=$("#runYaraScan");if(!path){out.textContent="Enter a local artifact path first.";return;}button.disabled=true;out.textContent="Running local YARA quick rules…";try{const r=await request("/api/forensics/yara-scan",{method:"POST",timeout:60000,body:JSON.stringify({path})});out.textContent=JSON.stringify(r.result,null,2);}catch(e){out.textContent=`YARA scan failed: ${e.message}`;}finally{button.disabled=false;}}

function initClock(){const tick=()=>setText("clock",new Intl.DateTimeFormat("en-GB",{hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:false,timeZone:"Asia/Amman"}).format(new Date())+" EEST");tick();setInterval(tick,1000);}
async function init(){Object.keys(viewConfig).forEach(buildDataView);bindEvents();loadChatThreads();window.addEventListener("popstate",()=>navigate(viewFromPath(),{fromRoute:true}));navigate(viewFromPath(),{fromRoute:true});applyPrivacyState();initClock();configureRefresh();renderSpark([]);drawEventChart([]);await loadCore();}
document.addEventListener("DOMContentLoaded",init);
