from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime
from enum import Enum

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentStatus(str, Enum):
    NEW = "new"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"

class Alert(BaseModel):
    source: str
    event_type: str
    description: str
    severity: Severity
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class Incident(BaseModel):
    id: str
    alert: Alert
    status: IncidentStatus = IncidentStatus.NEW
    automated_action_taken: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
