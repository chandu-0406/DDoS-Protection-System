# app.py

import csv
import os
from datetime import datetime
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pandas as pd

app = Flask(__name__)
LOG_FILE = "traffic_log.csv"
BLOCKED_IPS_FILE = "anomalies.csv"

# Ensure traffic log exists with headers
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "ip", "method", "path", "user_agent", "response_time"])

def get_blocked_ips():
    """Read blocked IPs from anomalies.csv (only 'ip' column)."""
    try:
        df = pd.read_csv(BLOCKED_IPS_FILE)
        return set(df["ip"].dropna().astype(str).tolist())
    except (FileNotFoundError, pd.errors.EmptyDataError):
        return set()

@app.before_request
def block_suspicious_ips():
    """Block any request from an IP in the latest anomalies list."""
    ip = request.remote_addr
    blocked = get_blocked_ips()
    if ip in blocked:
        # Return HTML if browser, JSON otherwise
        if request.accept_mimetypes.accept_html:
            return (
                "<h1>403 Forbidden</h1>"
                "<p>Your IP has been blocked due to suspicious activity.</p>", 
                403
            )
        return jsonify({"error": "Access Denied: Suspicious activity detected"}), 403

# Rate limiter: 10 requests per minute by default
limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"])

@app.before_request
def start_timer():
    request.start_time = datetime.now()

@app.after_request
def log_request(response):
    """Append each request’s details (with response time) to traffic_log.csv."""
    try:
        rt = (datetime.now() - request.start_time).total_seconds()
        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                request.remote_addr,
                request.method,
                request.path,
                request.user_agent.string,
                rt
            ])
    except Exception as e:
        print(f"Logging error: {e}")
    return response

@app.errorhandler(429)
def ratelimit_handler(e):
    return "Too many requests, slow down!", 429
from flask import render_template

# — Step 3a: Dynamic rate‑limit function —
def dynamic_limit():
    ip = request.remote_addr
    return "5 per minute" if ip in get_blocked_ips() else "20 per minute"

# Replace your static limiter setup with:
limiter = Limiter(get_remote_address, app=app)

# — Step 3b: Dashboard home route —
@app.route("/")
@limiter.limit(dynamic_limit)
def index():
    return render_template("index.html")

# — Step 3c: Data API endpoints for the dashboard —
@app.route("/logs")
def logs():
    df = pd.read_csv(LOG_FILE)
    return jsonify(df.tail(50).to_dict(orient="records"))

@app.route("/anomalies")
def anomalies():
    if not os.path.exists(BLOCKED_IPS_FILE):
        return jsonify([])
    df = pd.read_csv(BLOCKED_IPS_FILE).tail(50)
    return jsonify(df[["timestamp","ip","anomaly_score"]].to_dict(orient="records"))

@app.route("/blocked_ips")
def blocked():
    return jsonify(list(get_blocked_ips()))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
