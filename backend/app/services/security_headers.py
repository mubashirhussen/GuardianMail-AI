import re
from email.message import Message
from typing import Dict, Any, Tuple

class SecurityHeadersService:
    @staticmethod
    def analyze_authentication_headers(msg: Message) -> Tuple[Dict[str, Any], int, list]:
        """Perform validation of SPF, DKIM, DMARC, Return-Path, and Reply-To consistency (Module 10)."""
        findings = []
        score = 0
        
        from_header = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")
        received = msg.get_all("Received") or []
        
        # Parse SPF
        spf_header = msg.get("Received-SPF", "")
        auth_results = msg.get("Authentication-Results", "")
        
        spf_status = "none"
        dkim_status = "none"
        dmarc_status = "none"
        
        # Heuristics to parse SPF status
        if spf_header:
            spf_lower = spf_header.lower()
            if "pass" in spf_lower:
                spf_status = "pass"
            elif "fail" in spf_lower:
                spf_status = "fail"
                findings.append({
                    "indicator": "SPF authentication failed",
                    "detail": f"SPF result: {spf_header[:100]}",
                    "severity": "CRITICAL",
                    "score": 30
                })
                score += 30
            elif "softfail" in spf_lower:
                spf_status = "softfail"
                findings.append({
                    "indicator": "SPF softfail result",
                    "detail": f"SPF result: {spf_header[:100]}",
                    "severity": "HIGH",
                    "score": 20
                })
                score += 20
        else:
            # Check Authentication-Results for spf
            if auth_results:
                match = re.search(r'spf=(\w+)', auth_results.lower())
                if match:
                    spf_status = match.group(1)
                    if spf_status in ["fail", "hardfail"]:
                        findings.append({
                            "indicator": "SPF authentication failed",
                            "detail": f"Authentication-Results spf: {spf_status}",
                            "severity": "CRITICAL",
                            "score": 30
                        })
                        score += 30
            
            if spf_status == "none":
                findings.append({
                    "indicator": "No SPF record found",
                    "detail": "Email lacks SPF authentication validation",
                    "severity": "MEDIUM",
                    "score": 10
                })
                score += 10

        # Parse DKIM Signature
        dkim_signature = msg.get("DKIM-Signature", "")
        if dkim_signature:
            dkim_status = "present"
            # Extract status from Authentication-Results if present
            if auth_results:
                match = re.search(r'dkim=(\w+)', auth_results.lower())
                if match:
                    dkim_status = match.group(1)
                    if dkim_status == "fail":
                        findings.append({
                            "indicator": "DKIM signature invalid",
                            "detail": "Authentication-Results dkim: fail",
                            "severity": "HIGH",
                            "score": 25
                        })
                        score += 25
        else:
            findings.append({
                "indicator": "No DKIM signature",
                "detail": "Email is not signed with DKIM",
                "severity": "MEDIUM",
                "score": 10
            })
            score += 10

        # Parse DMARC
        if auth_results:
            match = re.search(r'dmarc=(\w+)', auth_results.lower())
            if match:
                dmarc_status = match.group(1)
                if dmarc_status == "fail":
                    findings.append({
                        "indicator": "DMARC check failed",
                        "detail": "Sender spoofing alert - DMARC authentication check failed",
                        "severity": "CRITICAL",
                        "score": 30
                    })
                    score += 30
            else:
                dmarc_status = "none"

        # Sender Domain Consistency Checks
        from_domain = SecurityHeadersService._extract_domain(from_header)
        reply_domain = SecurityHeadersService._extract_domain(reply_to) if reply_to else ""
        return_domain = SecurityHeadersService._extract_domain(return_path) if return_path else ""
        
        sender_alignment = True
        if reply_domain and from_domain and reply_domain != from_domain:
            sender_alignment = False
            findings.append({
                "indicator": "From/Reply-To domain mismatch",
                "detail": f"From: {from_domain} | Reply-To: {reply_domain}",
                "severity": "HIGH",
                "score": 25
            })
            score += 25
            
        if return_domain and from_domain and return_domain != from_domain:
            sender_alignment = False
            findings.append({
                "indicator": "From/Return-Path domain mismatch",
                "detail": f"From: {from_domain} | Return-Path: {return_domain}",
                "severity": "HIGH",
                "score": 20
            })
            score += 20

        # Routing check
        if len(received) > 6:
            findings.append({
                "indicator": "Excessive mail routing hops",
                "detail": f"{len(received)} mail servers parsed in routing path",
                "severity": "LOW",
                "score": 5
            })
            score += 5

        # Compile Pydantic model-compliant structures (Module 10)
        spf_pass = spf_status == "pass"
        dkim_pass = dkim_status in ["pass", "present"]
        dmarc_pass = dmarc_status == "pass"

        spf_obj = {
            "pass_value": spf_pass,
            "result": spf_status,
            "explanation": f"SPF validation result: {spf_status}"
        }
        
        dkim_obj = {
            "pass_value": dkim_pass,
            "domain": from_domain,
            "result": dkim_status,
            "explanation": f"DKIM signature is {dkim_status}"
        }
        
        dmarc_obj = {
            "pass_value": dmarc_pass,
            "domain": from_domain,
            "result": dmarc_status,
            "alignment": "aligned" if sender_alignment else "mismatched",
            "explanation": f"DMARC validation result: {dmarc_status}"
        }
        
        # Calculate auth score
        score_deductions = 0.0
        if not spf_pass:
            score_deductions += 0.4
        if not dkim_pass:
            score_deductions += 0.3
        if not sender_alignment:
            score_deductions += 0.3
            
        authentication_score = max(0.0, 1.0 - score_deductions)
        overall_pass = spf_pass and dkim_pass and sender_alignment

        auth_status = {
            "spf": spf_obj,
            "dkim": dkim_obj,
            "dmarc": dmarc_obj,
            "overall_authentication_pass": overall_pass,
            "authentication_score": authentication_score
        }
        
        return auth_status, score, findings

    @staticmethod
    def _extract_domain(email_address: str) -> str:
        """Helper to extract domain from text e.g., 'Name <user@domain.com>'"""
        match = re.search(r'@([\w.-]+)', email_address.lower())
        return match.group(1) if match else ""
