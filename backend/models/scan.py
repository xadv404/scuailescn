"""
SQL Audit Scanner - Pydantic models
"""
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from enum import Enum


class ScanStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class ScanRequest(BaseModel):
    urls: List[str]


class Finding(BaseModel):
    type: str
    severity: Severity
    location: str
    description: str
    impact: str
    recommendation: str
    evidence: Optional[Dict[str, Any]] = {}


class ScanSummary(BaseModel):
    scan_id: str
    target: str
    date: str
    status: ScanStatus
    risk_level: Optional[str] = "N/A"
    total_findings: int = 0


class ScanDetail(BaseModel):
    scan_id: str
    target: str
    date: str
    end_date: Optional[str] = None
    duration_seconds: Optional[float] = None
    status: ScanStatus
    findings: List[Finding] = []
    error: Optional[str] = None
