# E12.6 — MongoDB Production Configuration

## Indexes
* `response_decisions`: `organization_id` + `incident_id` + `status`
* `response_outcomes`: `organization_id` + `execution_id` + `decision_id` + `status`
* `response_policies`: `organization_id` + `policy_id` + `status`
* `response_policy_versions`: `organization_id` + `policy_id` + `version` DESC
* `soar_execution_requests`: `organization_id` + `execution_id` + `status` + `created_at` DESC

## Data Retention TTL Rules
* `response_outcomes`: 180 days TTL index.
* `soar_execution_requests`: 90 days TTL index.
* `response_optimizations`: 90 days TTL index.
* `response_tuning_recommendations`: 90 days TTL index.\n