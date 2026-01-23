from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from typing import List
import uuid
import logging
from datetime import datetime

from models import Alert, Incident, IncidentStatus, Severity
from playbooks.brute_force import run_brute_force_playbook
from config import settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SOAR-lite API")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify the actual frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for demo purposes
incidents: List[Incident] = []

async def process_alert(alert: Alert, incident_id: str):
    """
    Background task to process the alert and trigger playbooks.
    """
    logger.info(f"Processing alert {incident_id}: {alert.event_type}")
    
    actions_taken = "No automated action defined for this event type."
    
    # Simple playbook routing logic
    if "brute force" in alert.event_type.lower() or "authentication failure" in alert.event_type.lower():
        actions_taken = await run_brute_force_playbook(alert, settings.SLACK_WEBHOOK_URL)
    
    # Update the incident with the actions taken
    for inc in incidents:
        if inc.id == incident_id:
            inc.automated_action_taken = actions_taken
            inc.status = IncidentStatus.IN_PROGRESS if actions_taken else IncidentStatus.NEW
            logger.info(f"Updated incident {incident_id} with actions: {actions_taken}")
            break

@app.get("/")
async def root():
    return {"message": "SOAR-lite Orchestrator is running"}

@app.post("/webhooks/alerts", status_code=202)
async def receive_alert(alert: Alert, background_tasks: BackgroundTasks):
    incident_id = str(uuid.uuid4())
    new_incident = Incident(
        id=incident_id,
        alert=alert,
        status=IncidentStatus.NEW,
        created_at=datetime.utcnow()
    )
    incidents.append(new_incident)
    
    # Process the alert in the background
    background_tasks.add_task(process_alert, alert, incident_id)
    
    return {"incident_id": incident_id, "status": "accepted"}

@app.get("/incidents", response_model=List[Incident])
async def get_incidents():
    return incidents

@app.get("/incidents/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str):
    for inc in incidents:
        if inc.id == incident_id:
            return inc
    raise HTTPException(status_code=404, detail="Incident not found")

@app.post("/incidents/{incident_id}/resolve", response_model=Incident)
async def resolve_incident(incident_id: str):
    for inc in incidents:
        if inc.id == incident_id:
            inc.status = IncidentStatus.RESOLVED
            return inc
    raise HTTPException(status_code=404, detail="Incident not found")
