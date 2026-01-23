from playbooks.base import block_ip_on_mock_firewall, send_slack_notification
from models import Alert, Incident

async def run_brute_force_playbook(alert: Alert, slack_webhook: str = None):
    """
    Playbook for handling brute force attacks.
    1. Log the event.
    2. Block the source IP.
    3. Notify security team via Slack.
    """
    actions_taken = []
    
    if alert.source_ip:
        success = await block_ip_on_mock_firewall(alert.source_ip)
        if success:
            actions_taken.append(f"Blocked IP {alert.source_ip}")
    
    if slack_webhook:
        msg = f"🚨 *Brute Force Detected*\nSource: {alert.source}\nIP: {alert.source_ip}\nSeverity: {alert.severity}"
        await send_slack_notification(msg, slack_webhook)
        actions_taken.append("Sent Slack notification")
        
    return "; ".join(actions_taken)
