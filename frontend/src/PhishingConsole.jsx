import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  Shield, ShieldAlert, ShieldCheck, Upload, FileText, AlertTriangle,
  Radio, Link2, Server, Mail, ChevronRight, Zap, X
} from "lucide-react";

// ---------------------------------------------------------------------
// DESIGN TOKENS
// ---------------------------------------------------------------------
const C = {
  bg: "#0B0E13",
  panel: "#12171D",
  panelAlt: "#171D24",
  border: "#232B34",
  borderStrong: "#323C47",
  text: "#E8ECF1",
  textDim: "#8B96A3",
  textFaint: "#4E5964",
  safe: "#2DD4A7",
  warn: "#F2A93C",
  high: "#FF8A4C",
  crit: "#FF5A4E",
  info: "#4C9EFF",
};

const RISK_COLOR = { LOW: C.safe, MEDIUM: C.warn, HIGH: C.high, CRITICAL: C.crit };

// ---------------------------------------------------------------------
// SAMPLE EMAILS (for demo)
// ---------------------------------------------------------------------
const PHISH_SAMPLE = `Delivered-To: victim@example.com
Received: by 2002:a17:907:1c8f with SMTP id victim-recv; Sat, 01 Aug 2026 03:14:22 -0700
Received: from mail-relay-internal.example.com (mail-relay-internal.example.com. [10.10.0.5]) by mx.google.com with SMTPS id abc123; Sat, 01 Aug 2026 03:14:21 -0700
Received: from smtp-out-shady.freehosting-mail.ru (smtp-out-shady.freehosting-mail.ru. [185.220.101.47]) by mail-relay-internal.example.com with ESMTP id def456; Sat, 01 Aug 2026 03:14:18 -0700
Authentication-Results: mx.google.com; spf=fail (google.com: domain of noreply@paypa1-secure.com does not designate 185.220.101.47 as permitted sender) smtp.mailfrom=noreply@paypa1-secure.com; dkim=fail (signature did not verify) header.d=paypa1-secure.com; dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com
Return-Path: <bounce@paypa1-secure.com>
Reply-To: security-team@paypa1-secure.com
From: "PayPal Security" <alerts@paypal.com>
To: victim@example.com
Subject: URGENT: Your account has been suspended - Verify your identity immediately
Date: Sat, 01 Aug 2026 03:14:15 -0700
Message-ID: <a1b2c3d4@paypa1-secure.com>
Content-Type: text/plain; charset="UTF-8"

Dear Customer,

We have detected unusual activity on your account. Your account has been
suspended and will be permanently closed unless you verify your identity
immediately.

Click here to confirm your identity within 24 hours:
http://185.220.101.47/paypal-verify/login.php?session=8827aa

Failure to act now will result in permanent suspension. This is a final notice.

PayPal Security Team`;

const LEGIT_SAMPLE = `Delivered-To: teammate@example.com
Received: by 2002:a17:907:1c8f with SMTP id teammate-recv; Sat, 01 Aug 2026 09:02:10 -0700
Received: from mail-relay-internal.example.com (mail-relay-internal.example.com. [10.10.0.5]) by mx.google.com with SMTPS id ghi789; Sat, 01 Aug 2026 09:02:09 -0700
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) by mail-relay-internal.example.com with ESMTPS id jkl012; Sat, 01 Aug 2026 09:02:05 -0700
Authentication-Results: mx.google.com; spf=pass (google.com: domain of priya@company.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=priya@company.com; dkim=pass header.d=company.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=company.com
Return-Path: <priya@company.com>
From: "Priya Sharma" <priya@company.com>
To: teammate@example.com
Subject: Notes from today's sync
Date: Sat, 01 Aug 2026 09:02:00 -0700
Message-ID: <xyz987@company.com>
Content-Type: text/plain; charset="UTF-8"

Hi team,

Quick recap from today's sync: we're aligned on shipping the v2 API by
Friday. I'll send the updated doc by end of day. Let me know if I missed
anything.

Thanks,
Priya`;

// ---------------------------------------------------------------------
// ANALYSIS ENGINE (mirrors the Python CLI tool, in-browser)
// ---------------------------------------------------------------------
const URGENCY_KEYWORDS = [
  "urgent", "verify your account", "suspended", "act now", "immediately",
  "click here", "confirm your identity", "unusual activity",
  "password will expire", "limited time", "final notice",
  "your account has been", "security alert",
];
const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"];
const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;

function isPrivateIP(ip) {
  const p = ip.split(".").map(Number);
  if (p[0] === 10) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 127) return true;
  if (p[0] === 169 && p[1] === 254) return true;
  return false;
}

function unfoldHeaders(block) {
  const lines = block.split(/\r?\n/);
  const out = [];
  for (const line of lines) {
    if (/^[ \t]/.test(line) && out.length) out[out.length - 1] += " " + line.trim();
    else out.push(line);
  }
  return out;
}

function parseHeaders(rawText) {
  const sep = rawText.search(/\r?\n\r?\n/);
  const headerBlock = sep === -1 ? rawText : rawText.slice(0, sep);
  const body = sep === -1 ? "" : rawText.slice(sep).replace(/^\r?\n\r?\n/, "");
  const lines = unfoldHeaders(headerBlock);
  const map = {};
  for (const line of lines) {
    const m = line.match(/^([A-Za-z-]+):\s*(.*)$/);
    if (!m) continue;
    const key = m[1].toLowerCase();
    (map[key] = map[key] || []).push(m[2]);
  }
  return { headers: map, body };
}

function getDomain(addrField) {
  if (!addrField) return "";
  const m = addrField.match(/[\w.+-]+@([\w.-]+)/);
  return m ? m[1].toLowerCase() : "";
}

function analyzeRaw(rawText) {
  const { headers, body } = parseHeaders(rawText);
  const subject = (headers["subject"] || [""])[0];
  const from = (headers["from"] || [""])[0];
  const date = (headers["date"] || [""])[0];

  // auth results
  const auth = { spf: "none", dkim: "none", dmarc: "none" };
  for (const h of headers["authentication-results"] || []) {
    const re = /(spf|dkim|dmarc)\s*=\s*(\w+)/gi;
    let m;
    while ((m = re.exec(h))) {
      const mech = m[1].toLowerCase();
      if (auth[mech] === "none") auth[mech] = m[2].toLowerCase();
    }
  }

  // IPs from Received chain
  const ips = [];
  for (const h of headers["received"] || []) {
    const found = h.match(IPV4) || [];
    for (const ip of found) ips.push({ ip, private: isPrivateIP(ip) });
  }
  let originIP = null;
  for (let i = ips.length - 1; i >= 0; i--) {
    if (!ips[i].private) { originIP = ips[i]; break; }
  }
  if (!originIP && ips.length) originIP = ips[ips.length - 1];

  // domain alignment
  const fromDomain = getDomain(from);
  const replyToDomain = getDomain((headers["reply-to"] || [""])[0]);
  const returnPathDomain = getDomain((headers["return-path"] || [""])[0]);
  const mismatches = [];
  if (replyToDomain && replyToDomain !== fromDomain)
    mismatches.push(`Reply-To domain '${replyToDomain}' != From domain '${fromDomain}'`);
  if (returnPathDomain && returnPathDomain !== fromDomain)
    mismatches.push(`Return-Path domain '${returnPathDomain}' != From domain '${fromDomain}'`);

  // keywords
  const lowerText = `${subject} ${body}`.toLowerCase();
  const keywords = URGENCY_KEYWORDS.filter((k) => lowerText.includes(k));

  // links
  const linkFlags = [];
  const urls = body.match(/https?:\/\/[^\s"'<>]+/gi) || [];
  for (const url of urls) {
    const dm = url.match(/https?:\/\/([^/]+)/i);
    if (!dm) continue;
    const domain = dm[1].split(":")[0];
    if (new RegExp(`^${IPV4.source}$`).test(domain)) {
      linkFlags.push(`Link uses raw IP address instead of domain: ${url}`);
    } else if (SHORTENERS.includes(domain.toLowerCase())) {
      linkFlags.push(`Link uses a URL shortener (hides real destination): ${url}`);
    }
  }

  // scoring
  const breakdown = [];
  let score = 0;
  for (const mech of ["spf", "dkim", "dmarc"]) {
    const v = auth[mech];
    if (v === "fail" || v === "softfail") {
      score += 20;
      breakdown.push({ label: `${mech.toUpperCase()} = ${v}`, pts: 20 });
    } else if (v === "none") {
      score += 3;
      breakdown.push({ label: `${mech.toUpperCase()} = none (not checked/stamped)`, pts: 3 });
    } else {
      breakdown.push({ label: `${mech.toUpperCase()} = ${v}`, pts: 0 });
    }
  }
  const mismatchPts = Math.min(mismatches.length, 2) * 15;
  if (mismatchPts) {
    score += mismatchPts;
    mismatches.forEach((m) => breakdown.push({ label: m, pts: 15 }));
  }
  const kwPts = Math.min(keywords.length, 3) * 5;
  if (kwPts) {
    score += kwPts;
    breakdown.push({ label: `Urgency/pressure keywords: ${keywords.join(", ")}`, pts: kwPts });
  }
  const linkPts = Math.min(linkFlags.length, 2) * 15;
  if (linkPts) {
    score += linkPts;
    linkFlags.forEach((l) => breakdown.push({ label: l, pts: 15 }));
  }
  score = Math.max(0, Math.min(100, score));
  const risk = score >= 76 ? "CRITICAL" : score >= 51 ? "HIGH" : score >= 21 ? "MEDIUM" : "LOW";

  return { subject, from, date, auth, ips, originIP, fromDomain, replyToDomain, returnPathDomain, mismatches, keywords, linkFlags, breakdown, score, risk };
}

// ---------------------------------------------------------------------
// UI PIECES
// ---------------------------------------------------------------------
function AuthPill({ label, verdict }) {
  const color = verdict === "pass" ? C.safe : verdict === "none" ? C.textDim : C.crit;
  const bg = verdict === "pass" ? "rgba(45,212,167,0.1)" : verdict === "none" ? "rgba(139,150,163,0.1)" : "rgba(255,90,78,0.1)";
  return (
    <div className="flex items-center gap-2 rounded-lg px-3 py-2" style={{ background: bg, border: `1px solid ${color}33` }}>
      <span className="text-xs font-medium" style={{ color: C.textDim }}>{label}</span>
      <span className="text-xs font-medium" style={{ color, fontFamily: "ui-monospace, monospace" }}>{verdict}</span>
    </div>
  );
}

function Gauge({ score, risk, scanning }) {
  const r = 52, cx = 60, cy = 60;
  const circ = 2 * Math.PI * r;
  const color = RISK_COLOR[risk] || C.textDim;
  const offset = circ - (scanning ? 0 : score / 100) * circ;
  return (
    <div className="relative flex items-center justify-center" style={{ width: 140, height: 140 }}>
      <svg width="140" height="140" viewBox="0 0 120 120">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={C.border} strokeWidth="9" />
        <circle
          cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="9" strokeLinecap="round"
          strokeDasharray={`${circ} ${circ}`} strokeDashoffset={offset}
          transform={`rotate(-90 ${cx} ${cy})`}
          style={{ transition: "stroke-dashoffset 900ms cubic-bezier(.4,0,.2,1), stroke 400ms" }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-3xl font-medium" style={{ color: C.text, fontFamily: "ui-monospace, monospace" }}>
          {scanning ? "--" : score}
        </span>
        <span className="text-xs" style={{ color: C.textFaint }}>/ 100</span>
      </div>
    </div>
  );
}

function SignalLog({ breakdown, revealCount }) {
  return (
    <div className="flex flex-col gap-1.5">
      {breakdown.map((b, i) => (
        <div
          key={i}
          className="flex items-center justify-between gap-3 rounded-md px-3 py-2"
          style={{
            background: C.panelAlt,
            border: `1px solid ${C.border}`,
            opacity: i < revealCount ? 1 : 0,
            transform: i < revealCount ? "translateX(0)" : "translateX(-6px)",
            transition: `opacity 300ms ease ${i * 60}ms, transform 300ms ease ${i * 60}ms`,
          }}
        >
          <div className="flex items-center gap-2 min-w-0">
            <ChevronRight size={12} style={{ color: C.textFaint, flexShrink: 0 }} />
            <span className="text-xs truncate" style={{ color: C.textDim, fontFamily: "ui-monospace, monospace" }}>
              {b.label}
            </span>
          </div>
          <span
            className="text-xs font-medium flex-shrink-0"
            style={{ color: b.pts > 0 ? C.high : C.safe, fontFamily: "ui-monospace, monospace" }}
          >
            {b.pts > 0 ? `+${b.pts}` : "0"}
          </span>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------
// MAIN APP
// ---------------------------------------------------------------------
export default function PhishingConsole() {
  const [rawText, setRawText] = useState("");
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [revealCount, setRevealCount] = useState(0);
  const [dragActive, setDragActive] = useState(false);
  const debounceRef = useRef(null);
  const scanTimeoutRef = useRef(null);
  const fileInputRef = useRef(null);

  const runAnalysis = useCallback((text) => {
    if (!text.trim()) {
      setResult(null);
      setScanning(false);
      return;
    }
    setScanning(true);
    setRevealCount(0);
    clearTimeout(scanTimeoutRef.current);
    scanTimeoutRef.current = setTimeout(() => {
      const r = analyzeRaw(text);
      setResult(r);
      setScanning(false);
    }, 550);
  }, []);

  useEffect(() => {
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => runAnalysis(rawText), 350);
    return () => clearTimeout(debounceRef.current);
  }, [rawText, runAnalysis]);

  useEffect(() => {
    if (!result) return;
    let i = 0;
    const id = setInterval(() => {
      i += 1;
      setRevealCount(i);
      if (i >= result.breakdown.length) clearInterval(id);
    }, 70);
    return () => clearInterval(id);
  }, [result]);

  const handleFile = (file) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => setRawText(String(e.target.result || ""));
    reader.readAsText(file);
  };

  return (
    <div style={{ background: C.bg, minHeight: "100%", fontFamily: "ui-sans-serif, system-ui, sans-serif" }} className="w-full p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center rounded-lg" style={{ width: 36, height: 36, background: C.panel, border: `1px solid ${C.border}` }}>
            <Shield size={18} style={{ color: C.safe }} />
          </div>
          <div>
            <h1 className="text-base font-medium" style={{ color: C.text }}>Phishing email analyzer</h1>
            <p className="text-xs" style={{ color: C.textFaint }}>Real-time header, auth &amp; content triage</p>
          </div>
        </div>
        <div className="flex items-center gap-2 rounded-full px-3 py-1.5" style={{ background: C.panel, border: `1px solid ${C.border}` }}>
          <Radio size={11} style={{ color: rawText ? C.safe : C.textFaint }} className={rawText ? "animate-pulse" : ""} />
          <span className="text-xs" style={{ color: C.textDim }}>{scanning ? "Analyzing" : rawText ? "Live" : "Idle"}</span>
        </div>
      </div>

      <div className="grid gap-4" style={{ gridTemplateColumns: "minmax(0,1fr) minmax(0,1.15fr)" }}>
        {/* LEFT: input */}
        <div className="flex flex-col gap-3">
          <div className="flex gap-2">
            <button
              onClick={() => setRawText(PHISH_SAMPLE)}
              className="flex items-center gap-1.5 text-xs rounded-md px-3 py-2"
              style={{ background: C.panel, border: `1px solid ${C.border}`, color: C.textDim }}
            >
              <AlertTriangle size={12} style={{ color: C.high }} /> Load phishing sample
            </button>
            <button
              onClick={() => setRawText(LEGIT_SAMPLE)}
              className="flex items-center gap-1.5 text-xs rounded-md px-3 py-2"
              style={{ background: C.panel, border: `1px solid ${C.border}`, color: C.textDim }}
            >
              <ShieldCheck size={12} style={{ color: C.safe }} /> Load legit sample
            </button>
            {rawText && (
              <button
                onClick={() => setRawText("")}
                className="flex items-center gap-1.5 text-xs rounded-md px-3 py-2 ml-auto"
                style={{ background: C.panel, border: `1px solid ${C.border}`, color: C.textFaint }}
              >
                <X size={12} /> Clear
              </button>
            )}
          </div>

          <div
            onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
            onDragLeave={() => setDragActive(false)}
            onDrop={(e) => { e.preventDefault(); setDragActive(false); handleFile(e.dataTransfer.files?.[0]); }}
            className="rounded-xl flex flex-col"
            style={{
              background: C.panel,
              border: `1px solid ${dragActive ? C.info : C.border}`,
              minHeight: 420,
              transition: "border-color 200ms",
            }}
          >
            <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: `1px solid ${C.border}` }}>
              <div className="flex items-center gap-2">
                <FileText size={13} style={{ color: C.textDim }} />
                <span className="text-xs" style={{ color: C.textDim }}>Raw email source</span>
              </div>
              <button
                onClick={() => fileInputRef.current?.click()}
                className="flex items-center gap-1.5 text-xs rounded-md px-2.5 py-1.5"
                style={{ background: C.panelAlt, border: `1px solid ${C.border}`, color: C.textDim }}
              >
                <Upload size={11} /> Upload .eml
              </button>
              <input ref={fileInputRef} type="file" accept=".eml,.txt" className="hidden" onChange={(e) => handleFile(e.target.files?.[0])} />
            </div>
            <textarea
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder={"Paste raw email headers + body here, or drop a .eml file...\n\nTip: try one of the sample buttons above."}
              spellCheck={false}
              className="flex-1 w-full p-4 text-xs resize-none outline-none"
              style={{ background: "transparent", color: C.text, fontFamily: "ui-monospace, monospace", lineHeight: 1.6 }}
            />
          </div>
        </div>

        {/* RIGHT: results */}
        <div className="rounded-xl p-5 flex flex-col gap-4" style={{ background: C.panel, border: `1px solid ${C.border}`, minHeight: 420 }}>
          {!rawText.trim() && (
            <div className="flex-1 flex flex-col items-center justify-center gap-2 text-center py-16">
              <Zap size={22} style={{ color: C.textFaint }} />
              <p className="text-sm" style={{ color: C.textFaint }}>Waiting for email data</p>
              <p className="text-xs" style={{ color: C.textFaint, maxWidth: 260 }}>Results update automatically as you paste or edit headers</p>
            </div>
          )}

          {rawText.trim() && scanning && (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 py-16">
              <div className="rounded-full animate-spin" style={{ width: 28, height: 28, border: `2.5px solid ${C.border}`, borderTopColor: C.info }} />
              <p className="text-xs" style={{ color: C.textDim, fontFamily: "ui-monospace, monospace" }}>parsing headers // checking spf, dkim, dmarc...</p>
            </div>
          )}

          {rawText.trim() && !scanning && result && (
            <>
              <div className="flex items-center gap-5">
                <Gauge score={result.score} risk={result.risk} scanning={scanning} />
                <div className="flex flex-col gap-1.5 min-w-0">
                  <span
                    className="text-xs font-medium rounded-full px-2.5 py-1 w-fit"
                    style={{ background: `${RISK_COLOR[result.risk]}1A`, color: RISK_COLOR[result.risk] }}
                  >
                    {result.risk} RISK
                  </span>
                  <p className="text-sm truncate" style={{ color: C.text }}>{result.subject || "(no subject)"}</p>
                  <p className="text-xs truncate" style={{ color: C.textFaint }}>{result.from || "(no sender)"}</p>
                </div>
              </div>

              <div className="flex gap-2 flex-wrap">
                <AuthPill label="SPF" verdict={result.auth.spf} />
                <AuthPill label="DKIM" verdict={result.auth.dkim} />
                <AuthPill label="DMARC" verdict={result.auth.dmarc} />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div className="rounded-lg p-3" style={{ background: C.panelAlt, border: `1px solid ${C.border}` }}>
                  <div className="flex items-center gap-1.5 mb-1">
                    <Server size={11} style={{ color: C.textFaint }} />
                    <span className="text-xs" style={{ color: C.textFaint }}>Originating IP</span>
                  </div>
                  <p className="text-xs" style={{ color: C.text, fontFamily: "ui-monospace, monospace" }}>
                    {result.originIP ? result.originIP.ip : "not found"}
                  </p>
                  <p className="text-xs" style={{ color: result.originIP?.private ? C.textDim : C.warn }}>
                    {result.originIP ? (result.originIP.private ? "private / internal" : "public") : ""}
                  </p>
                </div>
                <div className="rounded-lg p-3" style={{ background: C.panelAlt, border: `1px solid ${C.border}` }}>
                  <div className="flex items-center gap-1.5 mb-1">
                    <Mail size={11} style={{ color: C.textFaint }} />
                    <span className="text-xs" style={{ color: C.textFaint }}>Domain alignment</span>
                  </div>
                  <p className="text-xs" style={{ color: result.mismatches.length ? C.crit : C.safe }}>
                    {result.mismatches.length ? `${result.mismatches.length} mismatch(es)` : "aligned"}
                  </p>
                  <p className="text-xs truncate" style={{ color: C.textFaint, fontFamily: "ui-monospace, monospace" }}>
                    {result.fromDomain || "-"}
                  </p>
                </div>
              </div>

              {result.linkFlags.length > 0 && (
                <div className="rounded-lg p-3 flex items-start gap-2" style={{ background: "rgba(255,90,78,0.07)", border: `1px solid ${C.crit}33` }}>
                  <Link2 size={13} style={{ color: C.crit, marginTop: 1, flexShrink: 0 }} />
                  <p className="text-xs" style={{ color: C.textDim }}>{result.linkFlags.length} suspicious link(s) detected in body</p>
                </div>
              )}

              <div className="flex flex-col gap-2">
                <span className="text-xs" style={{ color: C.textFaint }}>Signal breakdown</span>
                <SignalLog breakdown={result.breakdown} revealCount={revealCount} />
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
