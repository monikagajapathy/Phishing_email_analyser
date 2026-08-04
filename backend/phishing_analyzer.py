

import argparse
import email
import ipaddress
import json
import re
import sys
from email.message import Message
from email.utils import parseaddr, getaddresses

# --------------------------------------------------------------------------
# 1. LOAD THE EMAIL
# --------------------------------------------------------------------------

def load_eml(path: str) -> Message:
    """Reads a raw .eml file from disk and parses it into a Message object."""
    with open(path, "rb") as f:
        raw_bytes = f.read()
    # BytesParser understands headers + multipart bodies + attachments
    msg = email.message_from_bytes(raw_bytes)
    return msg


# --------------------------------------------------------------------------
# 2. AUTHENTICATION RESULTS (SPF / DKIM / DMARC)
# --------------------------------------------------------------------------
# Real mail servers (Gmail, Outlook, corporate mail gateways) already do the
# heavy lifting of SPF/DKIM/DMARC validation and stamp the *result* into the
# "Authentication-Results" header before the message reaches an inbox.
# We parse that header rather than re-implementing DNS + crypto validation
# ourselves -- this is also exactly what SOC / blue-team tooling does.

AUTH_RESULT_PATTERN = re.compile(
    r"(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE
)


def parse_authentication_results(msg: Message) -> dict:
    """
    Extracts spf/dkim/dmarc verdicts (pass/fail/softfail/neutral/none) from
    all Authentication-Results headers. There can be more than one header if
    the message passed through several mail relays.
    """
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    headers = msg.get_all("Authentication-Results", [])

    for header in headers:
        for match in AUTH_RESULT_PATTERN.finditer(header):
            mechanism, verdict = match.group(1).lower(), match.group(2).lower()
            # keep the first (closest-hop / most authoritative) verdict found
            if results[mechanism] == "none":
                results[mechanism] = verdict

    return results


# --------------------------------------------------------------------------
# 3. ORIGINATING IP EXTRACTION
# --------------------------------------------------------------------------
# The "Received" header chain records every server hop the email passed
# through, oldest hop at the bottom, newest at the top. The ORIGINATING IP
# is usually in the LAST (bottom-most / earliest) Received header, since
# that is closest to the actual sender before it entered trusted infra.

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)


def extract_ips(msg: Message) -> list:
    """Pulls every IPv4 address out of the Received header chain, in order
    from newest hop to oldest hop, and flags whether each is public/private."""
    received_headers = msg.get_all("Received", [])
    found = []

    for header in received_headers:
        for ip in IP_PATTERN.findall(header):
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                continue
            found.append({
                "ip": ip,
                "is_private": ip_obj.is_private,
                "is_reserved": ip_obj.is_reserved or ip_obj.is_loopback,
            })

    return found


def originating_ip(ip_list: list) -> dict | None:
    """The last public IP in the chain is the best guess at the true sender."""
    for entry in reversed(ip_list):
        if not entry["is_private"] and not entry["is_reserved"]:
            return entry
    return ip_list[-1] if ip_list else None


# --------------------------------------------------------------------------
# 4. DOMAIN / IDENTITY ALIGNMENT CHECKS
# --------------------------------------------------------------------------

def get_domain(address: str) -> str:
    """Extracts and lowercases the domain part of an email address."""
    _, addr = parseaddr(address or "")
    if "@" in addr:
        return addr.split("@")[-1].lower()
    return ""


def check_domain_alignment(msg: Message) -> dict:
    """Compares the domains in From / Reply-To / Return-Path.
    A mismatch is a classic phishing signal: the visible sender name says
    one thing, but replies or bounces are routed to an attacker's domain."""
    from_domain = get_domain(msg.get("From", ""))
    reply_to_domain = get_domain(msg.get("Reply-To", ""))
    return_path_domain = get_domain(msg.get("Return-Path", ""))

    mismatches = []
    if reply_to_domain and reply_to_domain != from_domain:
        mismatches.append(f"Reply-To domain '{reply_to_domain}' != From domain '{from_domain}'")
    if return_path_domain and return_path_domain != from_domain:
        mismatches.append(f"Return-Path domain '{return_path_domain}' != From domain '{from_domain}'")

    return {
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "mismatches": mismatches,
    }


# --------------------------------------------------------------------------
# 5. CONTENT HEURISTICS (subject / body)
# --------------------------------------------------------------------------

URGENCY_KEYWORDS = [
    "urgent", "verify your account", "suspended", "act now", "immediately",
    "click here", "confirm your identity", "unusual activity", "password will expire",
    "limited time", "final notice", "your account has been", "security alert",
]

SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def get_body_text(msg: Message) -> str:
    """Walks a (possibly multipart) message and returns the plain-text body."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    return part.get_payload(decode=True).decode(errors="ignore")
                except Exception:
                    continue
        return ""
    try:
        return msg.get_payload(decode=True).decode(errors="ignore")
    except Exception:
        return str(msg.get_payload())


def scan_keywords(subject: str, body: str) -> list:
    text = f"{subject} {body}".lower()
    return [kw for kw in URGENCY_KEYWORDS if kw in text]


def scan_links(body: str) -> list:
    """Flags links that use a raw IP address instead of a domain, or that
    route through a known URL-shortener (both common phishing/obfuscation
    tricks used to hide the real destination)."""
    flags = []
    for url in URL_PATTERN.findall(body):
        domain_match = re.search(r"https?://([^/]+)", url)
        if not domain_match:
            continue
        domain = domain_match.group(1).split(":")[0]
        if IP_PATTERN.fullmatch(domain):
            flags.append(f"Link uses raw IP address instead of domain: {url}")
        elif domain.lower() in SHORTENER_DOMAINS:
            flags.append(f"Link uses a URL shortener (hides real destination): {url}")
    return flags


# --------------------------------------------------------------------------
# 6. SCORING ENGINE
# --------------------------------------------------------------------------
# Each rule adds points toward a 0-100 "suspiciousness score". This is a
# transparent, additive rule-based model -- every point is explainable,
# which matters a lot when you have to defend your design to judges.

SCORE_RULES = {
    "spf_fail":        20,
    "dkim_fail":        20,
    "dmarc_fail":       20,
    "auth_missing":     10,   # no Authentication-Results header at all
    "domain_mismatch":  15,   # per mismatch, capped
    "urgency_keyword":   5,   # per keyword, capped
    "suspicious_link":  15,   # per link, capped
}


def compute_score(auth: dict, alignment: dict, keywords: list, link_flags: list) -> dict:
    breakdown = []
    score = 0

    for mechanism in ("spf", "dkim", "dmarc"):
        verdict = auth[mechanism]
        if verdict in ("fail", "softfail"):
            pts = SCORE_RULES[f"{mechanism}_fail"]
            score += pts
            breakdown.append((f"{mechanism.upper()} = {verdict}", pts))
        elif verdict == "none":
            pts = SCORE_RULES["auth_missing"] // 3  # small partial penalty per mechanism
            score += pts
            breakdown.append((f"{mechanism.upper()} = none (not checked/stamped)", pts))
        else:
            breakdown.append((f"{mechanism.upper()} = {verdict}", 0))

    mismatch_points = min(len(alignment["mismatches"]), 2) * SCORE_RULES["domain_mismatch"]
    if mismatch_points:
        score += mismatch_points
        for m in alignment["mismatches"]:
            breakdown.append((m, SCORE_RULES["domain_mismatch"]))

    kw_points = min(len(keywords), 3) * SCORE_RULES["urgency_keyword"]
    if kw_points:
        score += kw_points
        breakdown.append((f"Urgency/pressure keywords found: {', '.join(keywords)}", kw_points))

    link_points = min(len(link_flags), 2) * SCORE_RULES["suspicious_link"]
    if link_points:
        score += link_points
        for lf in link_flags:
            breakdown.append((lf, SCORE_RULES["suspicious_link"]))

    score = max(0, min(100, score))

    if score >= 76:
        risk = "CRITICAL"
    elif score >= 51:
        risk = "HIGH"
    elif score >= 21:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {"score": score, "risk": risk, "breakdown": breakdown}


# --------------------------------------------------------------------------
# 7. MAIN ANALYSIS PIPELINE
# --------------------------------------------------------------------------

def analyze(path: str) -> dict:
    msg = load_eml(path)

    subject = msg.get("Subject", "")
    sender = msg.get("From", "")
    date = msg.get("Date", "")

    auth = parse_authentication_results(msg)
    ips = extract_ips(msg)
    origin_ip = originating_ip(ips)
    alignment = check_domain_alignment(msg)
    body = get_body_text(msg)
    keywords = scan_keywords(subject, body)
    link_flags = scan_links(body)
    result = compute_score(auth, alignment, keywords, link_flags)

    return {
        "file": path,
        "subject": subject,
        "from": sender,
        "date": date,
        "authentication": auth,
        "ips": ips,
        "originating_ip": origin_ip,
        "domain_alignment": alignment,
        "keywords_found": keywords,
        "link_flags": link_flags,
        "score": result["score"],
        "risk": result["risk"],
        "breakdown": result["breakdown"],
    }


# --------------------------------------------------------------------------
# 8. REPORTING (console + HTML)
# --------------------------------------------------------------------------

RISK_COLOR = {"LOW": "#639922", "MEDIUM": "#BA7517", "HIGH": "#D85A30", "CRITICAL": "#A32D2D"}


def print_console_report(r: dict):
    bar_len = 40
    filled = int(bar_len * r["score"] / 100)
    bar = "#" * filled + "-" * (bar_len - filled)

    print("=" * 60)
    print(f"PHISHING ANALYSIS REPORT: {r['file']}")
    print("=" * 60)
    print(f"Subject : {r['subject']}")
    print(f"From    : {r['from']}")
    print(f"Date    : {r['date']}")
    print("-" * 60)
    print(f"SPF={r['authentication']['spf']}  DKIM={r['authentication']['dkim']}  DMARC={r['authentication']['dmarc']}")
    if r["originating_ip"]:
        ip_note = " (private/internal)" if r["originating_ip"]["is_private"] else " (public)"
        print(f"Originating IP: {r['originating_ip']['ip']}{ip_note}")
    else:
        print("Originating IP: not found in headers")
    print("-" * 60)
    print(f"SCORE: [{bar}] {r['score']}/100  RISK: {r['risk']}")
    print("-" * 60)
    print("Breakdown:")
    for reason, pts in r["breakdown"]:
        sign = f"+{pts}" if pts else "  0"
        print(f"  {sign:>4}  {reason}")
    print("=" * 60)


def generate_html_report(r: dict, out_path: str):
    color = RISK_COLOR[r["risk"]]
    rows = "".join(
        f"<tr><td>{reason}</td><td class='pts'>{'+' + str(pts) if pts else '0'}</td></tr>"
        for reason, pts in r["breakdown"]
    )
    origin = r["originating_ip"]
    origin_html = (
        f"{origin['ip']} ({'private/internal' if origin['is_private'] else 'public'})"
        if origin else "Not found"
    )

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Phishing Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, sans-serif; background:#f4f4f2; margin:0; padding:32px; color:#2c2c2a; }}
  .card {{ max-width:720px; margin:0 auto; background:#fff; border-radius:12px; padding:32px; box-shadow:0 1px 3px rgba(0,0,0,.1); }}
  h1 {{ font-size:20px; margin:0 0 4px; }}
  .meta {{ color:#5f5e5a; font-size:14px; margin-bottom:20px; }}
  .score-wrap {{ display:flex; align-items:center; gap:20px; margin:20px 0; }}
  .score-num {{ font-size:42px; font-weight:700; color:{color}; }}
  .risk-badge {{ display:inline-block; padding:4px 14px; border-radius:20px; background:{color}22; color:{color}; font-weight:600; font-size:13px; letter-spacing:.5px; }}
  .bar-bg {{ flex:1; height:14px; background:#eee; border-radius:7px; overflow:hidden; }}
  .bar-fill {{ height:100%; background:{color}; width:{r['score']}%; }}
  table {{ width:100%; border-collapse:collapse; margin-top:16px; font-size:14px; }}
  td {{ padding:8px 6px; border-bottom:1px solid #eee; }}
  .pts {{ text-align:right; font-weight:600; white-space:nowrap; width:50px; }}
  .auth-row span {{ display:inline-block; margin-right:16px; padding:4px 10px; border-radius:6px; font-size:13px; font-weight:600; }}
  .pass {{ background:#EAF3DE; color:#3B6D11; }}
  .fail {{ background:#FCEBEB; color:#791F1F; }}
  .none {{ background:#F1EFE8; color:#5F5E5A; }}
</style></head>
<body>
  <div class="card">
    <h1>Phishing analysis report</h1>
    <div class="meta">{r['file']}</div>
    <div><b>Subject:</b> {r['subject']}<br><b>From:</b> {r['from']}<br><b>Date:</b> {r['date']}</div>

    <div class="score-wrap">
      <div class="score-num">{r['score']}</div>
      <div class="bar-bg"><div class="bar-fill"></div></div>
      <div class="risk-badge">{r['risk']} RISK</div>
    </div>

    <div class="auth-row">
      <span class="{'pass' if r['authentication']['spf']=='pass' else ('none' if r['authentication']['spf']=='none' else 'fail')}">SPF: {r['authentication']['spf']}</span>
      <span class="{'pass' if r['authentication']['dkim']=='pass' else ('none' if r['authentication']['dkim']=='none' else 'fail')}">DKIM: {r['authentication']['dkim']}</span>
      <span class="{'pass' if r['authentication']['dmarc']=='pass' else ('none' if r['authentication']['dmarc']=='none' else 'fail')}">DMARC: {r['authentication']['dmarc']}</span>
    </div>

    <p><b>Originating IP:</b> {origin_html}</p>

    <table>
      <tr><td><b>Signal</b></td><td class="pts"><b>Points</b></td></tr>
      {rows}
    </table>
  </div>
</body></html>"""

    with open(out_path, "w") as f:
        f.write(html)


# --------------------------------------------------------------------------
# 9. CLI ENTRY POINT
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Analyze a raw .eml file for phishing indicators.")
    parser.add_argument("eml_file", help="Path to the raw .eml file")
    parser.add_argument("--html", help="Path to write an HTML report", default=None)
    parser.add_argument("--json", help="Path to write a JSON report", default=None)
    args = parser.parse_args()

    result = analyze(args.eml_file)
    print_console_report(result)

    if args.html:
        generate_html_report(result, args.html)
        print(f"\nHTML report written to: {args.html}")

    if args.json:
        # originating_ip / ips are already JSON-safe dicts
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2)
        print(f"JSON report written to: {args.json}")


if __name__ == "__main__":
    main()
