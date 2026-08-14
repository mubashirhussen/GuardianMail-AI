import json
import logging
from typing import List, Optional, Dict, Any
from app.core.tenant_context import TenantContext
from app.database.cache import cache_manager
from app.database.connection import db_manager
from app.repositories.security_policy_repo import SecurityPolicyRepository

logger = logging.getLogger("guardianmail.policy_engine")

class PolicyEngineService:
    """Centralized policy engine executing hierarchy evaluations and caching decisions."""

    def __init__(self):
        pass

    @property
    def policy_repo(self) -> SecurityPolicyRepository:
        return SecurityPolicyRepository(db_manager.db)

    async def get_active_policies(self, org_id: str, policy_type: str) -> List[Dict[str, Any]]:
        """Fetch active policies from cache or fall back to database storage."""
        cache_key = f"active_policies:{org_id}:{policy_type}"
        cached = await cache_manager.get(cache_key)
        if cached:
            # Already deserialized by CacheManager
            return cached

        policies = await self.policy_repo.get_active_policies_by_org_and_type(org_id, policy_type)
        await cache_manager.set(cache_key, policies, expire_seconds=1800)
        return policies

    async def invalidate_policy_cache(self, org_id: str, policy_type: str) -> None:
        """Evict cached policy parameters."""
        await cache_manager.delete(f"active_policies:{org_id}:{policy_type}")

    def evaluate_condition(self, payload: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        """Evaluate a single rule condition against the request context/payload."""
        field = condition.get("field")
        operator = condition.get("operator")
        expected = condition.get("value")

        if field not in payload:
            return False

        actual = payload[field]

        try:
            if operator == "gte":
                return float(actual) >= float(expected)
            elif operator == "lte":
                return float(actual) <= float(expected)
            elif operator == "gt":
                return float(actual) > float(expected)
            elif operator == "lt":
                return float(actual) < float(expected)
            elif operator == "eq":
                return str(actual).lower().strip() == str(expected).lower().strip()
            elif operator == "contains":
                return str(expected).lower().strip() in str(actual).lower().strip()
            elif operator == "not_contains":
                return str(expected).lower().strip() not in str(actual).lower().strip()
        except (ValueError, TypeError):
            return False

        return False

    async def evaluate(
        self, 
        policy_type: str, 
        context: TenantContext, 
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Evaluate applicable policies with hierarchy precedence.
        Hierarchy: User Override > Team Policy > Department Policy > Org Policy > Global Default
        Precedence: Explicit DENY overrides ALLOW.
        """
        # Load policies for tenant
        policies = await self.get_active_policies(context.organization_id, policy_type)

        # Categorize policies by specificity hierarchy
        user_policy = None
        team_policy = None
        dept_policy = None
        org_policy = None

        for p in policies:
            if p.get("user_id") == context.user_id:
                user_policy = p
            elif p.get("team") == context.team and context.team:
                team_policy = p
            elif p.get("department") == context.department and context.department:
                dept_policy = p
            elif not p.get("user_id") and not p.get("team") and not p.get("department"):
                org_policy = p

        hierarchy = [
            ("user_override", user_policy),
            ("team_policy", team_policy),
            ("department_policy", dept_policy),
            ("organization_policy", org_policy)
        ]

        fired_actions = []
        explanations = []

        # Process each active policy level in the hierarchy
        for level, policy in hierarchy:
            if not policy:
                continue

            for idx, rule in enumerate(policy.get("rules", [])):
                conditions = rule.get("conditions", [])
                match = True
                for cond in conditions:
                    if not self.evaluate_condition(payload, cond):
                        match = False
                        break
                
                if match:
                    action = rule.get("action", "ALLOW").upper()
                    description = rule.get("description", f"Rule #{idx+1} matched")
                    fired_actions.append((level, action, description))
                    explanations.append(f"[{level.upper()}] {description} -> {action}")

        # Check for explicit DENY in any fired rules (Deny overrides everything)
        for level, action, desc in fired_actions:
            if action == "DENY" or action == "BLOCK":
                return {
                    "decision": "DENY",
                    "explanation": explanations or ["Blocked by explicit deny override rule."],
                    "source": level
                }

        # If no explicit deny, take the decision from the most specific fired action
        if fired_actions:
            # Fired actions are ordered from user_override to organization_policy
            level, action, desc = fired_actions[0]
            return {
                "decision": action,
                "explanation": explanations,
                "source": level
            }

        # If no policy rules matched, fall back to global default policies
        global_decision = self.get_global_default(policy_type, payload)
        return {
            "decision": global_decision["decision"],
            "explanation": [f"[GLOBAL_DEFAULT] {global_decision['reason']}"],
            "source": "global_default"
        }

    def get_global_default(self, policy_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Provides default fallbacks for unconfigured policies."""
        if policy_type == "email_security":
            # Risk >= 80 -> REQUIRE_REVIEW, else ALLOW
            risk = payload.get("risk_score", 0)
            if risk >= 80:
                return {"decision": "REQUIRE_REVIEW", "reason": "Risk score is >= 80"}
            return {"decision": "ALLOW", "reason": "Default clean email verdict"}

        elif policy_type == "url_security":
            reputation = payload.get("reputation", "clean")
            if reputation in ["malicious", "block"]:
                return {"decision": "DENY", "reason": "URL is classified as malicious by default"}
            elif reputation == "suspicious":
                return {"decision": "REQUIRE_REVIEW", "reason": "Suspicious reputation warrants analyst review"}
            return {"decision": "ALLOW", "reason": "URL is clean"}

        elif policy_type == "attachment":
            ext = str(payload.get("extension", "")).lower().strip()
            if ext in [".exe", ".sh", ".bat", ".scr", ".vbs"]:
                return {"decision": "DENY", "reason": "Dangerous file extension blocked by default"}
            return {"decision": "ALLOW", "reason": "Allowed file format"}

        elif policy_type == "ai_analysis":
            # Enable external AI processing by default with redaction
            return {"decision": "ALLOW", "reason": "AI scanning enabled with PII redaction by default"}

        elif policy_type == "data_retention":
            return {"decision": "ALLOW", "reason": "Apply default retention rules: 365 days audits"}

        return {"decision": "ALLOW", "reason": "Default system fallback ALLOW"}

policy_engine = PolicyEngineService()
