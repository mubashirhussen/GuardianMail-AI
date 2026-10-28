from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from app.models.base import BaseMongoModel

class TestCase(BaseModel):
    """Explicit event payload and expected outcomes for rule validation."""
    input_event: Dict[str, Any] = Field(..., description="Mock telemetry event data")
    expected_match: bool = Field(..., description="Whether rule conditions are expected to match")
    expected_severity: Optional[str] = Field(None, description="Optional expected severity to match")
    expected_technique: Optional[str] = Field(None, description="Optional expected MITRE technique")

class DetectionTest(BaseMongoModel):
    """Detection testing configuration settings."""
    organization_id: str = Field(..., description="Target tenant organization ID")
    rule_id: str = Field(..., description="Associated detection rule ID key")
    detection_version_id: Optional[str] = Field(None, description="Specific rule version ID hex if fixed")
    version_number: Optional[int] = Field(None, description="Specific rule version number if fixed")
    name: str = Field(..., min_length=3, description="Test name description")
    description: Optional[str] = None
    test_type: str = Field("controlled_event", description="controlled_event, dataset, historical_replay")
    test_cases: List[TestCase] = Field(default_factory=list, description="List of explicit test cases")
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    max_events: Optional[int] = Field(100, description="Max events limit bound")
    status: str = Field("PENDING", description="PENDING, RUNNING, PASSED, FAILED, ERROR, CANCELLED")

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class DetectionTestResult(BaseMongoModel):
    """Persisted outcome details representing execution runs statistics."""
    organization_id: str
    test_id: str = Field(..., description="ObjectId string of the DetectionTest")
    rule_id: str
    version_number: int
    status: str = Field(..., description="PASSED, FAILED, ERROR, CANCELLED")
    start_time: datetime
    end_time: datetime
    duration_ms: float
    total_events_evaluated: int
    match_count: int
    expected_match_count: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    match_rate: float
    errors: List[str] = Field(default_factory=list)

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class DetectionTestMatch(BaseMongoModel):
    """Single matching telemetry item recorded during evaluation."""
    organization_id: str
    test_id: str
    result_id: str
    event_id: Optional[str] = None
    timestamp: datetime
    event_type: str
    source: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    version_number: int
    status: str = Field("UNKNOWN", description="TP, FP, UNKNOWN")

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
