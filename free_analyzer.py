# FREE VERSION - Simple Log Analyzer
import json
from datetime import datetime, timedelta

MAX_REQUESTS = 10
TIME_WINDOW_SECONDS = 60

def analyze_logs(log_data):
    print("--- Analyzing Logs (Free Version) ---")
    ip_counts = {}
    suspicious_ips = ["192.168.1.105", "203.0.113.50"] # Sample suspicious IPs

    for log in log_data:
        ip = log['ip']
        if ip in suspicious_ips:
            print(f"[THREAT] Detected blacklisted IP: {ip}")

        if ip not in ip_counts:
            ip_counts[ip] = []

        timestamp = datetime.fromisoformat(log['timestamp'])
        ip_counts[ip].append(timestamp)

        # Rate limit check
        recent_requests = [t for t in ip_counts[ip] if timestamp - t < timedelta(seconds=TIME_WINDOW_SECONDS)]
        if len(recent_requests) > MAX_REQUESTS:
            print(f"[THREAT] Rate limit exceeded for IP: {ip} ({len(recent_requests)} requests)")

    print("\n--- Analysis Complete ---")
    print("This is a free version with limited features. For advanced analysis including threat scoring and stateful correlation, please check out our Premium Version.")

if __name__ == '__main__':
    sample_logs = [
        {'ip': '8.8.8.8', 'timestamp': datetime.now().isoformat()},
        {'ip': '203.0.113.50', 'timestamp': (datetime.now() - timedelta(seconds=10)).isoformat()},
    ]
    analyze_logs(sample_logs)
