import requests
import json
import sys

URL = "http://localhost:8000/webhooks/alerts"

alerts = [
    {
        "source": "Wazuh",
        "event_type": "Brute Force Attack",
        "description": "Multiple failed SSH login attempts detected for user 'admin' from 192.168.1.105",
        "severity": "high",
        "source_ip": "192.168.1.105",
        "user_id": "admin",
        "metadata": {"attempts": 15, "port": 22}
    },
    {
        "source": "Azure AD",
        "event_type": "Suspicious Login",
        "description": "Login from unusual location (Nigeria) for user 'john.doe@example.com'",
        "severity": "medium",
        "source_ip": "45.123.45.67",
        "user_id": "john.doe@example.com",
        "metadata": {"location": "Lagos, NG"}
    },
    {
        "source": "Suricata",
        "event_type": "Malware C2 Communication",
        "description": "Outbound connection to known malicious domain detected from workstation-01",
        "severity": "critical",
        "source_ip": "10.0.0.50",
        "metadata": {"domain": "malicious-c2.com", "destination_ip": "185.199.110.153"}
    }
]

def send_alert(alert):
    print(f"Sending alert: {alert['event_type']}...")
    try:
        response = requests.post(URL, json=alert)
        response.raise_for_status()
        print(f"Success! Incident ID: {response.json().get('incident_id')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Send a specific alert by index if provided
        idx = int(sys.argv[1])
        if 0 <= idx < len(alerts):
            send_alert(alerts[idx])
        else:
            print(f"Invalid index. Choose 0 to {len(alerts)-1}")
    else:
        # Send all alerts
        for alert in alerts:
            send_alert(alert)
