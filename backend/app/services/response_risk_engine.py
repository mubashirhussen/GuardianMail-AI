import math
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("guardianmail.response_risk_engine")

DEFAULT_WEIGHTS = {
    "detection": 0.25,
    "threat_intel": 0.25,
    "campaign": 0.20,
    "ueba": 0.15,
    "investigation": 0.15
}

class ResponseRiskEngine:
    @staticmethod
    def validate_score(val: Any) -> float:
        """Validate numeric score sanity, instantly rejecting NaN, Infinity, negative, or excessive values."""
        if val is None:
            return 0.0
        try:
            f_val = float(val)
        except (ValueError, TypeError):
            raise ValueError(f"Score must be a valid number, got {val}")

        if math.isnan(f_val):
            raise ValueError("NaN is not a valid score value")
        if math.isinf(f_val):
            raise ValueError("Infinity is not a valid score value")
        if f_val < 0.0:
            raise ValueError(f"Negative score values ({f_val}) are rejected")
        if f_val > 100.0:
            raise ValueError(f"Score values past maximum 100 ({f_val}) are rejected")

        return f_val

    @staticmethod
    def calculate_decision(
        organization_id: str,
        signals: Dict[str, Any],
        weights: Optional[Dict[str, float]] = None
    ) -> Dict[str, Any]:
        """Compute dynamic risk, confidence, severity, and safety-guided recommended actions (E11.8.2)."""
        active_weights = weights or DEFAULT_WEIGHTS

        # 1. Tenant boundary checks & Input normalization
        normalized_scores = {}
        contributions = {}
        raw_signals = {}
        
        for key in ["detection", "threat_intel", "campaign", "ueba", "investigation"]:
            sig_data = signals.get(key) or {}
            
            # Tenant cross-contamination protection
            sig_org = sig_data.get("organization_id")
            if sig_org and sig_org != organization_id:
                raise ValueError(f"Cross-tenant signal detected! Organization mismatch: {sig_org} vs {organization_id}")

            raw_score = sig_data.get("score", 0.0)
            normalized_score = ResponseRiskEngine.validate_score(raw_score)
            
            normalized_scores[key] = normalized_score
            raw_signals[key] = sig_data
            
            weight = active_weights.get(key, 0.0)
            contributions[key] = normalized_score * weight

        # 2. Weighted Risk Score calculation
        total_risk = sum(contributions.values())
        final_risk_score = round(total_risk)

        # 3. Confidence Score calculation (evaluating signal count & agreement)
        provided_signals = {k: v for k, v in raw_signals.items() if v.get("score") is not None}
        valid_signals_count = len(provided_signals)
        
        # Source reliability mapping over provided signals only
        base_confidence = 50.0
        if valid_signals_count > 0:
            sum_conf = sum(ResponseRiskEngine.validate_score(s.get("confidence", 50.0)) for s in provided_signals.values())
            base_confidence = sum_conf / valid_signals_count

        # Signal Agreement check (Corroboration boost vs Conflict penalty)
        agreement_modifier = 0.0
        
        det_risk = normalized_scores["detection"]
        intel_risk = normalized_scores["threat_intel"]
        camp_risk = normalized_scores["campaign"]

        # Corroboration: multiple high-risk indicators increase confidence
        if det_risk >= 70.0 and intel_risk >= 70.0:
            agreement_modifier += 15.0
            if camp_risk >= 70.0:
                agreement_modifier += 10.0
                
        # Signal conflict: high detection risk but clean threat feeds decreases confidence
        elif det_risk >= 70.0 and intel_risk <= 20.0:
            agreement_modifier -= 20.0

        confidence_score = max(0.0, min(100.0, base_confidence + agreement_modifier))
        confidence_score = round(confidence_score)

        # 4. Severity Classification
        if final_risk_score >= 75:
            severity = "CRITICAL"
        elif final_risk_score >= 50:
            severity = "HIGH"
        elif final_risk_score >= 25:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # 5. Recommended Action mapping
        if valid_signals_count == 0:
            recommended_action = "NO_ACTION"
        elif severity == "CRITICAL":
            # Prefer Host isolation if campaign signal exists, else credential resets
            recommended_action = "ISOLATE_HOST" if normalized_scores["campaign"] >= 50.0 else "RESET_CREDENTIAL"
        elif severity == "HIGH":
            recommended_action = "QUARANTINE_EMAIL" if normalized_scores["detection"] >= 50.0 else "BLOCK_INDICATOR"
        elif severity == "MEDIUM":
            recommended_action = "QUARANTINE_EMAIL" if intel_risk >= 50.0 else "NOTIFY_ANALYST"
        else:
            recommended_action = "MONITOR"

        # 6. Safety rules (Confidence-based downgrades)
        original_action = recommended_action
        if confidence_score < 40.0 and recommended_action in ["ISOLATE_HOST", "RESET_CREDENTIAL", "REVOKE_SESSION"]:
            logger.warning(f"Confidence score {confidence_score} below minimum threshold. Downgrading critical action {recommended_action} to NOTIFY_ANALYST.")
            recommended_action = "NOTIFY_ANALYST"

        # 7. Approval requirement determination
        low_risk_actions = ["NO_ACTION", "MONITOR", "NOTIFY_ANALYST", "EXPORT_GRC_EVIDENCE"]
        approval_required = recommended_action not in low_risk_actions

        # 8. Decision trace construction
        decision_trace = {
            "weights": active_weights,
            "normalized_signals": normalized_scores,
            "contributions": contributions,
            "original_recommended_action": original_action,
            "signal_agreement_modifier": agreement_modifier,
            "valid_signals_count": valid_signals_count
        }

        return {
            "risk_score": final_risk_score,
            "confidence_score": confidence_score,
            "severity": severity,
            "recommended_action": recommended_action,
            "approval_required": approval_required,
            "decision_trace": decision_trace
        }
