#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI-Powered Web Application Firewall
-----------------------------------
- AI threat detection (XSS, SQLi, DDoS)
- DDoS sliding-window limiter
- MySQL + OS-level (nftables/ipset) IP blocking
- Flask UI + stats/metrics API
- Network monitoring via Scapy (optional)

Author: Ata Sharef (Sharevex)
"""

import os
import sys
import time
import signal
import logging
from datetime import timedelta

from flask import Flask, request, jsonify, session, redirect, url_for, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv

# === Load .env if exists
load_dotenv()

# === Logging
logger = logging.getLogger("firewall")
logging.basicConfig(
    level=logging.DEBUG if os.getenv("FW_DEBUG", "0") == "1" else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# === Imports (local modules)
from ai_detector import detect_attack
from ip_blocker_db import MySQLIPBlocker

# === ENV Config
PORT = int(os.getenv("FW_PORT", 8080))
BLOCK_TTL = int(os.getenv("FW_BLOCK_TTL", 300))
DDOS_WINDOW = int(os.getenv("FW_DDOS_WINDOW", 60))
DDOS_MAX = int(os.getenv("FW_DDOS_MAX", 20))
SECRET_KEY = os.getenv("APP_SECRET_KEY", "change-me")
TRUST_PROXY = os.getenv("FW_TRUST_PROXY", "1") == "1"

# === Global state
ddos_window = {}
stats = {
    "total": 0,
    "blocked": 0,
    "ai_blocked": 0,
    "ddos_blocked": 0,
    "ip_requests": {},
    "ip_blocks": {},
}
blocker = None

# === Flask App
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)

if TRUST_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app)

# === Utils

def get_ip() -> str:
    return (
        request.headers.get("CF-Connecting-IP") or
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or
        request.headers.get("X-Real-IP") or
        request.remote_addr or "unknown"
    )

def is_ddos(ip: str) -> bool:
    now = time.time()
    window = ddos_window.setdefault(ip, [])
    window[:] = [t for t in window if now - t <= DDOS_WINDOW]
    window.append(now)
    return len(window) > DDOS_MAX

def log_block(ip: str, reason: str):
    stats["blocked"] += 1
    stats["ip_blocks"][ip] = stats["ip_blocks"].get(ip, 0) + 1
    logger.warning(f"🚫 Blocked {ip} — {reason}")
    blocker.block_ip(ip, reason=reason)

# === Middleware

@app.before_request
def before_request():
    path = request.path
    ip = get_ip()
    stats["total"] += 1
    stats["ip_requests"][ip] = stats["ip_requests"].get(ip, 0) + 1

    # Skip health and login endpoints
    if path.startswith("/static") or path in ["/favicon.ico", "/health", "/login"]:
        return

    # DDoS protection
    if is_ddos(ip):
        stats["ddos_blocked"] += 1
        log_block(ip, "DDoS threshold exceeded")
        return jsonify({"status": "blocked", "reason": "DDoS"}), 429

    # AI threat detection
    body = request.get_data(as_text=True)
    query = request.query_string.decode("utf-8", errors="ignore")

    for part, label in [(path, "path"), (query, "query"), (body, "body")]:
        threat = detect_attack(part)
        if threat != 0:
            stats["ai_blocked"] += 1
            log_block(ip, f"AI detected threat in {label}")
            return jsonify({
                "status": "blocked",
                "reason": f"AI detected malicious {label}",
                "ip": ip,
                "threat_code": threat
            }), 403

# === Routes

@app.route("/")
def index():
    return jsonify({"status": "ok", "message": "Firewall active"})

@app.route("/stats")
def stats_view():
    return jsonify(stats)

@app.route("/health")
def health():
    return jsonify({"status": "healthy", "timestamp": time.time()})

@app.route("/login", methods=["GET", "POST"])
def login():
    # Placeholder (use secureauth module if needed)
    if request.method == "POST":
        session["user"] = request.form.get("username", "admin")
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", stats=stats)

# === Lifecycle

def graceful_shutdown(*_):
    logger.info("🛑 Firewall shutting down...")
    if blocker:
        blocker.stop()
    sys.exit(0)

def start():
    global blocker
    blocker = MySQLIPBlocker(default_ttl_seconds=BLOCK_TTL)
    blocker.start_background_sync()
    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)
    logger.info("🔥 Firewall started")
    app.run(host="0.0.0.0", port=PORT, threaded=True)

if __name__ == "__main__":
    start()
