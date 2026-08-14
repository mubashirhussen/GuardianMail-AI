# E11 — Detection Engineering REST API

The Detection Engine foundation exposes the following endpoints:

## 1. REST Endpoints

### List Rules
- **Method / Path**: `GET /api/v1/detections`
- **Query Parameters**:
  - `status` (Optional)
  - `severity` (Optional)
  - `data_source` (Optional)
  - `author` (Optional)
  - `search` (Optional)
- **Response**: List of filtered `DetectionRule` objects.

### Create Rule
- **Method / Path**: `POST /api/v1/detections`
- **Payload**:
  - `rule_id`: str (min_length=3)
  - `name`: str (min_length=3)
  - `description`: str
  - `severity`: str ("LOW", "MEDIUM", "HIGH", "CRITICAL")
  - `confidence`: str ("LOW", "MEDIUM", "HIGH")
  - `data_sources`: List[str]
  - `conditions`: Dict[str, Any]
  - `time_window`: int
  - `mitre_attack_techniques`: List[str]
  - `false_positive_guidance`: str
- **Response**: 201 Created rule details.

### Get Rule Details & History
- **Method / Path**: `GET /api/v1/detections/{id}`
- **Response**: `DetectionRule` document populated with its `versions` list and `audits` log entries.

### Update Rule Properties
- **Method / Path**: `PATCH /api/v1/detections/{id}`
- **Payload**: `DetectionUpdateRequest` fields with optional `change_info` comment.
- **Response**: Updated rule document with version incremented.

### Status Transitions
- **Method / Path**: `POST /api/v1/detections/{id}/status`
- **Payload**: `StatusTransitionRequest` containing target status.
- **Response**: Rule details with new status applied if valid.
