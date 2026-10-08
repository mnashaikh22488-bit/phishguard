"""
PhishGuard – Phishing Awareness & Suspicious Link Reporting System
Flask backend with SQLite, link/email analysis, reporting, stats, and AI chat fallback.
"""

import os
import re
import sqlite3
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Paths & database setup
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "phishguard.db")


def get_db():
    """Open a SQLite connection with row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create data folder and tables if they do not exist."""
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_type TEXT NOT NULL,
            content TEXT NOT NULL,
            reason TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            links_checked INTEGER DEFAULT 0,
            emails_checked INTEGER DEFAULT 0,
            reports_submitted INTEGER DEFAULT 0,
            high_risk_detections INTEGER DEFAULT 0
        )
        """
    )

    cur.execute("SELECT COUNT(*) AS c FROM stats")
    if cur.fetchone()["c"] == 0:
        cur.execute(
            "INSERT INTO stats (id, links_checked, emails_checked, reports_submitted, high_risk_detections) VALUES (1, 0, 0, 0, 0)"
        )

    conn.commit()
    conn.close()


def update_stat(field, increment=1):
    """Increment a counter in the stats table."""
    conn = get_db()
    conn.execute(f"UPDATE stats SET {field} = {field} + ? WHERE id = 1", (increment,))
    conn.commit()
    conn.close()


def get_stats():
    """Return current dashboard stats."""
    conn = get_db()
    row = conn.execute("SELECT * FROM stats WHERE id = 1").fetchone()
    conn.close()
    if not row:
        return {
            "links_checked": 0,
            "emails_checked": 0,
            "reports_submitted": 0,
            "high_risk_detections": 0,
        }
    return dict(row)


# ---------------------------------------------------------------------------
# Link analysis (structure only – never visit the URL)
# ---------------------------------------------------------------------------
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "account",
    "update", "secure", "banking", "password", "confirm", "wallet",
    "paypal", "appleid", "microsoft", "amazon", "netflix", "support",
    "unlock", "suspended", "limited", "alert", "security", "credential",
    "authenticate", "auth", "webscr", "ebayisapi", "cgi-bin",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "shorturl.at", "rebrand.ly",
    "cutt.ly", "tiny.cc", "rb.gy", "t.ly",
]


def analyze_link(url: str) -> dict:
    """Analyze URL text/structure only. Returns risk score and indicators."""
    indicators = []
    score = 0
    url = (url or "").strip()

    if not url:
        return {
            "score": 0,
            "classification": "LOW RISK",
            "indicators": ["No URL provided."],
            "disclaimer": "A Low Risk result does not guarantee that a website is safe.",
        }

    # Basic parse – add scheme if missing for urlparse
    parse_url = url if "://" in url else "http://" + url
    try:
        parsed = urlparse(parse_url)
    except Exception:
        return {
            "score": 70,
            "classification": "HIGH RISK",
            "indicators": ["URL could not be parsed – structure looks invalid."],
            "disclaimer": "A Low Risk result does not guarantee that a website is safe.",
        }

    host = (parsed.hostname or "").lower()
    path = (parsed.path or "") + (parsed.query or "")
    full = url.lower()

    # 1. HTTPS
    if not full.startswith("https://") and "://" in full:
        score += 15
        indicators.append("Does not use HTTPS (or scheme is missing/non-HTTPS).")
    elif "://" not in full:
        score += 10
        indicators.append("No protocol specified – treat carefully.")

    # 2. Length
    if len(url) > 100:
        score += 15
        indicators.append("URL is unusually long.")
    elif len(url) > 75:
        score += 8
        indicators.append("URL is quite long.")

    # 3. IP address instead of domain
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host or ""):
        score += 25
        indicators.append("Uses an IP address instead of a domain name.")

    # 4. Suspicious keywords
    found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]
    if found_kw:
        score += min(20, 5 * len(found_kw))
        indicators.append(f"Suspicious keyword(s) detected: {', '.join(found_kw[:5])}.")

    # 5. @ symbol (credential phishing trick)
    if "@" in url:
        score += 25
        indicators.append("Contains '@' symbol – can hide the real destination.")

    # 6. Punycode / IDN
    if "xn--" in host or "xn--" in full:
        score += 20
        indicators.append("Punycode (xn--) detected – possible lookalike domain.")

    # 7. Excessive subdomains
    if host:
        parts = host.split(".")
        if len(parts) >= 4:
            score += 15
            indicators.append("Excessive subdomains – structure looks unusual.")
        elif len(parts) == 3 and parts[0] not in ("www", "mail", "web", "app"):
            # mild signal only
            pass

    # 8. URL shorteners
    if any(s in host for s in URL_SHORTENERS if host):
        score += 20
        indicators.append("Known URL shortener – destination is hidden.")

    # 9. Unusual characters
    if re.search(r"[^\w\-./:?&=%#~@+]", url):
        # Allow common URL chars; flag odd ones
        odd = re.findall(r"[^\w\-./:?&=%#~@+]", url)
        if odd:
            score += 10
            indicators.append("Unusual characters in the URL.")

    # 10. Suspicious path
    if re.search(r"(login|signin|verify|account|secure|update|password|confirm)", path, re.I):
        score += 10
        if "Suspicious keyword" not in " ".join(indicators):
            indicators.append("Path suggests login/verification page.")

    # 11. Multiple redirects / encoded
    if url.count("%") > 3:
        score += 10
        indicators.append("Heavy URL encoding – may hide content.")

    # 12. Hyphen-heavy or lookalike
    if host and host.count("-") >= 3:
        score += 10
        indicators.append("Domain contains many hyphens.")

    score = min(100, max(0, score))

    if score <= 29:
        classification = "LOW RISK"
    elif score <= 59:
        classification = "SUSPICIOUS"
    else:
        classification = "HIGH RISK"

    if not indicators:
        indicators.append("No strong structural red flags found (structure-only check).")

    return {
        "score": score,
        "classification": classification,
        "indicators": indicators,
        "disclaimer": "A Low Risk result does not guarantee that a website is safe. This tool only inspects URL text/structure and never visits the link.",
    }


# ---------------------------------------------------------------------------
# Email / message analysis
# ---------------------------------------------------------------------------
def analyze_email(text: str) -> dict:
    """Analyze pasted email/message for common phishing patterns."""
    indicators = []
    score = 0
    text = (text or "").strip()
    lower = text.lower()

    if not text:
        return {
            "score": 0,
            "classification": "LOW RISK",
            "indicators": ["No message provided."],
            "explanation": "Paste a message to analyze.",
        }

    # Urgency
    urgency_words = [
        "urgent", "immediately", "act now", "within 24 hours", "expire",
        "suspended", "locked", "limited time", "asap", "right now",
        "final notice", "last chance", "account will be closed",
    ]
    if any(w in lower for w in urgency_words):
        score += 15
        indicators.append("Urgency language")

    # Threats
    threat_words = [
        "legal action", "police", "arrest", "lawsuit", "terminate",
        "ban your account", "permanent ban", "fine",
    ]
    if any(w in lower for w in threat_words):
        score += 15
        indicators.append("Threat language")

    # Password / credentials
    if re.search(r"\b(password|passcode|credentials|login details)\b", lower):
        score += 20
        indicators.append("Password / credential request")

    # OTP / PIN / CVV
    if re.search(r"\b(otp|one[- ]time|verification code|pin|cvv|cvc|security code)\b", lower):
        score += 20
        indicators.append("OTP / PIN / CVV request")

    # Payment
    if re.search(r"\b(wire transfer|gift card|bitcoin|crypto|send money|payment|bank details|iban)\b", lower):
        score += 15
        indicators.append("Payment / money request")

    # Links
    urls = re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", text, re.I)
    if urls:
        score += 10
        indicators.append("Contains link(s)")
        # quick structure check on first link
        link_result = analyze_link(urls[0])
        if link_result["score"] >= 40:
            score += 10
            indicators.append("Suspicious link structure")

    # Generic greeting
    if re.search(r"^(dear customer|dear user|dear valued|hello user|hi there)\b", lower):
        score += 8
        indicators.append("Generic greeting")

    # Fake rewards
    if re.search(r"\b(you('ve| have)? won|prize|reward|free gift|claim now|lottery)\b", lower):
        score += 15
        indicators.append("Fake reward / prize language")

    # Account verification
    if re.search(r"\b(verify your account|confirm your (identity|account)|update your (account|information))\b", lower):
        score += 12
        indicators.append("Account verification request")

    # Excessive punctuation / caps
    if text.count("!") >= 3 or (len(re.findall(r"[A-Z]{4,}", text)) >= 2):
        score += 5
        indicators.append("Excessive punctuation or shouting")

    # Social engineering
    if re.search(r"\b(click (here|below)|open the attachment|download (now|the file))\b", lower):
        score += 10
        indicators.append("Social engineering call-to-action")

    score = min(100, max(0, score))

    if score <= 29:
        classification = "LOW RISK"
    elif score <= 59:
        classification = "SUSPICIOUS"
    else:
        classification = "HIGH RISK"

    if not indicators:
        indicators.append("No strong phishing patterns detected.")

    explanation = (
        "This analysis looks for common phishing patterns in the text only. "
        "It does not prove a message is safe or malicious. When in doubt, "
        "contact the organization through an official channel you already trust."
    )

    return {
        "score": score,
        "classification": classification,
        "indicators": indicators,
        "explanation": explanation,
    }


# ---------------------------------------------------------------------------
# Local AI fallback (no external API required)
# ---------------------------------------------------------------------------
def local_ai_reply(message: str) -> str:
    """Simple rule-based replies for cybersecurity awareness."""
    msg = (message or "").strip()
    lower = msg.lower()

    if not msg:
        return "Please type a question about phishing, links, or online safety."

    # Detect pasted URL
    url_match = re.search(r"https?://[^\s]+|www\.[^\s]+", msg, re.I)
    if url_match or (lower.startswith("http") and " " not in msg.strip()):
        url = url_match.group(0) if url_match else msg.strip()
        result = analyze_link(url)
        lines = [
            f"I analyzed the **structure** of that URL (I never visit links).",
            f"**Risk score:** {result['score']}/100 — **{result['classification']}**",
            "Reasons:",
        ]
        for ind in result["indicators"]:
            lines.append(f"• {ind}")
        lines.append(result["disclaimer"])
        return "\n".join(lines)

    # Long paste that looks like an email
    if len(msg) > 120 and any(
        w in lower for w in ["dear", "account", "verify", "password", "click", "urgent", "otp"]
    ):
        result = analyze_email(msg)
        lines = [
            "I checked that message for common phishing patterns.",
            f"**Risk score:** {result['score']}/100 — **{result['classification']}**",
            "Detected indicators:",
        ]
        for ind in result["indicators"]:
            lines.append(f"• {ind}")
        lines.append(result["explanation"])
        return "\n".join(lines)

    # Topic replies
    if "phishing" in lower and ("what" in lower or "is" in lower):
        return (
            "Phishing is a social engineering attack where scammers pretend to be a trusted "
            "person or organization to trick you into sharing passwords, OTPs, card details, "
            "or clicking a malicious link. Always verify through official channels."
        )

    if "otp" in lower or "one-time" in lower:
        return (
            "Never share an OTP, PIN, or verification code with anyone who contacts you. "
            "Banks and legitimate services will not ask you to send your OTP by message or phone. "
            "If you receive an unexpected OTP request, ignore it and contact the company via their official app or website."
        )

    if "clicked" in lower or "i clicked" in lower or "after clicking" in lower:
        return (
            "If you clicked a suspicious link: 1) Do not enter any passwords or codes. "
            "2) Close the page. 3) Run a malware scan if you downloaded anything. "
            "4) Change passwords from a known-safe device if you entered credentials. "
            "5) Contact your bank if financial details might be exposed. "
            "6) Report the incident using our Report page."
        )

    if "identify" in lower or "how do i" in lower or "red flag" in lower:
        return (
            "Common red flags: unexpected messages, extreme urgency, suspicious domains, "
            "requests for passwords/OTPs, unexpected payment asks, fake rewards, and unknown attachments. "
            "Hover over links to preview the real URL, and never trust lookalike domains."
        )

    if "link" in lower and ("suspicious" in lower or "safe" in lower or "check" in lower):
        return (
            "Paste the full URL here or use the **Check Link** page. I only analyze structure "
            "(HTTPS, length, keywords, IP hosts, shorteners, etc.) and never open the link. "
            "A low score does not mean the site is safe."
        )

    if "email" in lower:
        return (
            "Paste the email text into the **Check Email** page or here. Look for urgency, "
            "credential requests, generic greetings, and unexpected links. Verify any request "
            "through the official website or app—not via links in the message."
        )

    if "report" in lower:
        return (
            "Use the **Report** section to submit suspicious links, phishing emails, or scam messages. "
            "Reports are stored for awareness tracking. Do not open the suspicious content yourself."
        )

    # Default
    return (
        "I can help with phishing awareness, suspicious links, scam emails, OTPs, and what to do "
        "after a click. Try: “What is phishing?”, “Is it safe to share an OTP?”, or paste a URL/message. "
        "I give educational guidance only—not a guarantee of safety."
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/check-link", methods=["POST"])
def api_check_link():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    result = analyze_link(url)
    update_stat("links_checked")
    if result["score"] >= 60:
        update_stat("high_risk_detections")
    return jsonify(result)


@app.route("/api/check-email", methods=["POST"])
def api_check_email():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    result = analyze_email(text)
    update_stat("emails_checked")
    if result["score"] >= 60:
        update_stat("high_risk_detections")
    return jsonify(result)


@app.route("/api/report", methods=["POST"])
def api_report():
    data = request.get_json(silent=True) or {}
    report_type = (data.get("report_type") or "").strip()
    content = (data.get("content") or "").strip()
    reason = (data.get("reason") or "").strip()

    if not report_type or not content:
        return jsonify({"ok": False, "error": "Report type and content are required."}), 400

    allowed = {"Suspicious Link", "Phishing Email", "Scam Message", "Other"}
    if report_type not in allowed:
        return jsonify({"ok": False, "error": "Invalid report type."}), 400

    conn = get_db()
    conn.execute(
        "INSERT INTO reports (report_type, content, reason, created_at) VALUES (?, ?, ?, ?)",
        (report_type, content, reason, datetime.utcnow().isoformat() + "Z"),
    )
    conn.commit()
    conn.close()
    update_stat("reports_submitted")

    return jsonify({"ok": True, "message": "Report submitted successfully."})


@app.route("/api/chat", methods=["POST"])
def api_chat():
    """
    API-ready chat endpoint.
    Later you can replace local_ai_reply with a call to an external AI API.
    Never put API keys in frontend JavaScript.
    """
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")
    try:
        reply = local_ai_reply(message)
        return jsonify({"reply": reply})
    except Exception:
        return jsonify({"reply": "Sorry, something went wrong. Please try again."}), 500


@app.route("/api/stats", methods=["GET"])
def api_stats():
    return jsonify(get_stats())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="127.0.0.1", port=5000)