import httpx
import logging

logger = logging.getLogger(__name__)

async def send_slack_notification(message: str, webhook_url: str):
    """
    Sends a notification to Slack.
    """
    if not webhook_url:
        logger.warning("Slack webhook URL not configured. Skipping notification.")
        return
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(webhook_url, json={"text": message})
            response.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")

async def block_ip_on_mock_firewall(ip: str):
    """
    Simulates blocking an IP address.
    """
    logger.info(f"MOCK FIREWALL: Blocking IP {ip}")
    # In a real scenario, this would call an API or run an SSH command
    return True

async def disable_azure_ad_user(user_id: str):
    """
    Simulates disabling a user in Azure AD.
    """
    logger.info(f"MOCK AZURE AD: Disabling user {user_id}")
    # In a real scenario, this would use Microsoft Graph API
    return True
