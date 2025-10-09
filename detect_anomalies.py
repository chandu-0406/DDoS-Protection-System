# detect_anomalies.py

import pandas as pd
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta

LOG_FILE = "traffic_log.csv"
OUTPUT_FILE = "anomalies.csv"

# Load logged traffic data
try:
    df = pd.read_csv(LOG_FILE)
except FileNotFoundError:
    print("🚨 Log file not found. Run your Flask app to collect logs first.")
    exit()

if df.empty:
    print("🚨 No traffic data found! Run your Flask app to collect logs first.")
    exit()

# Convert timestamp column and (optional) filter last 24 hours
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
# df = df[df["timestamp"] >= (datetime.now() - timedelta(hours=24))]

# Drop rows with missing response_time
df = df.dropna(subset=["response_time"])

# If not enough data, skip detection
if len(df) < 10:
    print("⚠️ Not enough data points to detect anomalies.")
    exit()

# Train Isolation Forest on response_time
model = IsolationForest(contamination=0.05, random_state=42)
model.fit(df[["response_time"]])

# Compute anomaly scores and labels
df["anomaly_score"] = model.decision_function(df[["response_time"]])
df["is_anomaly"]   = model.predict(df[["response_time"]])  # -1 = anomaly, 1 = normal

# Extract anomalies (where is_anomaly == -1)
anomalies = df[df["is_anomaly"] == -1]
if not anomalies.empty:
    print("🚨 Detected anomalies:")
    print(anomalies[["timestamp", "ip", "method", "path", "anomaly_score"]])
    # Save only the unique IPs for blocking
    anomalies[["ip"]].drop_duplicates().to_csv(OUTPUT_FILE, index=False)
else:
    print("✅ No anomalies detected.")

# Save full log with scores for auditing
df.to_csv("traffic_log_with_scores.csv", index=False)
