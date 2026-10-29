"""
Major Recent Cyber Threat Advisories & Customer Defense Knowledge Base.
Provides structured real-world incidents from recent days for customer awareness,
actionable defense guides, and CERT-In / National Cyber Crime complaint bundle generation.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import uuid

MAJOR_ADVISORIES: List[Dict[str, Any]] = [
    {
        "id": "ADV-2026-IN01",
        "title": "India Post Failed Delivery SMS (Smishing) Campaign",
        "category": "Smishing / Postal Scam",
        "severity": "CRITICAL",
        "incident_date": "Active Campaign (Past 48 Hours)",
        "threat_vector": "SMS · Shortened URLs (.top, .vip, .icu) · Cloned Payment Portals",
        "target_audience": "All Mobile Subscribers & Online Shoppers",
        "cert_in_ref": "CERT-In Advisory CIAD-2026-0041 / MHA Cyber Dost Alert",
        "legal_sections": "IT Act Section 66D, 420 IPC (Cheating by Personation)",
        "summary": "Nationwide surge of spoofed SMS pretending to be India Post stating parcels cannot be delivered due to address errors, demanding a ₹25 re-delivery charge on fake websites to steal banking credentials and OTPs.",
        "modus_operandi": [
            "1. Victim receives an urgent SMS from headers like 'CP-INDPOST', 'VK-IPOST', or +91 personal numbers claiming: 'Your package is arrived at the sorting warehouse, but could not be delivered due to incomplete address. Please update your address within 24 hours: https://indiapost-parcel.top/update'.",
            "2. Clicking the link opens a counterfeit clone of the official India Post tracking portal with official logos, Ashoka emblem, and simulated parcel tracking numbers.",
            "3. The site asks for the victim's name, home address, and a nominal 'Re-delivery fee' of ₹25 or ₹30.",
            "4. When the victim enters credit/debit card or UPI details, fraudsters immediately trigger an unauthorized transaction of ₹25,000 to ₹1,00,000 and intercept the OTP via keylogging or fake payment screens."
        ],
        "sample_indicators": [
            "indiapost-parcel.top",
            "indiapost-address-update.vip",
            "post-delivery-service.icu",
            "india-post-redelivery.net",
            "Sender IDs: CP-IPOST, VM-DELIVR, +91 92892 xxxxx"
        ],
        "protection_steps": [
            "India Post NEVER asks for address modification or re-delivery fees via SMS links with third-party domain extensions (.top, .vip, .icu, .xyz).",
            "Only visit the official government website directly: https://www.indiapost.gov.in and verify consignment numbers only on the official portal.",
            "Never enter your card CVV, ATM PIN, or NetBanking OTP on any webpage reached through an SMS or WhatsApp link.",
            "India Post tracking numbers always follow standard Universal Postal Union format (e.g. 2 letters, 9 digits, 2 letters: EE123456789IN)."
        ],
        "what_to_do_if_affected": [
            "IMMEDIATELY dial 1930 (National Cyber Crime Helpline) within the 'Golden Hour' (first 2-3 hours) so the bank transaction can be frozen in the CFCFRMS portal.",
            "Call your bank customer care or use mobile banking app to permanently BLOCK your compromised debit/credit card and NetBanking credentials.",
            "File a formal incident report on https://cybercrime.gov.in and forward the phishing SMS to report@phishing.gov.in."
        ]
    },
    {
        "id": "ADV-2026-IN02",
        "title": "Electricity Bill Power Disconnection APK / Remote Access Fraud",
        "category": "Malware / APK Trojan",
        "severity": "CRITICAL",
        "incident_date": "Active Nationwide Threat (Reported Daily)",
        "threat_vector": "WhatsApp / SMS · Malicious Android APKs · Screen-Sharing Apps (AnyDesk/QuickSupport)",
        "target_audience": "Residential & Commercial Electricity Consumers",
        "cert_in_ref": "CERT-In Advisory CIAD-2026-0038 / State Discom Alerts",
        "legal_sections": "IT Act Section 43/66 (Computer Contaminant/Hacking), 420 IPC",
        "summary": "Urgent SMS warning of power cut at 9:30 PM tonight due to unpaid electricity bill, directing victims to call a fake 'Power Officer' who tricks them into downloading an APK or remote screen viewer to drain bank accounts.",
        "modus_operandi": [
            "1. Consumer receives a panic-inducing SMS: 'Dear consumer, your electricity power will be disconnected tonight at 9:30 PM from the power office because your previous month bill was not updated. Immediately contact our electricity officer Mr. Verma at 9876543210'.",
            "2. When the frightened consumer calls the number, the impersonator speaks with authority and instructs them to pay an outstanding fee of ₹10 to prevent imminent blackout.",
            "3. The scammer sends a link on WhatsApp to download an APK file named 'BijliBill_Update.apk' or asks them to install 'QuickSupport' / 'AnyDesk' from Play Store.",
            "4. The malware gains accessibility permissions, reads incoming SMS OTPs silently, and while the user attempts a ₹10 test payment, the fraudster steals the full bank balance in seconds."
        ],
        "sample_indicators": [
            "BijliBill_Update.apk",
            "Suvidha_Power_Bill.apk",
            "Urgent phone numbers listed in body rather than official DISCOM 1912 helpline",
            "Payment links pointing to personal UPI handles (@okaxis, @ybl) instead of state DISCOM merchant accounts"
        ],
        "protection_steps": [
            "State electricity boards (BESCOM, TNEB, MSEDCL, BSES, Tata Power, etc.) NEVER send disconnection notices from personal 10-digit mobile numbers.",
            "Disconnection notices are served formally in writing with a mandatory 15-day prior notice period under the Electricity Act 2003.",
            "NEVER install any APK file sent over WhatsApp or SMS. Always pay utility bills directly through official utility mobile apps or the authorized Bharat Bill Payment System (BBPS).",
            "NEVER install screen-sharing software (AnyDesk, TeamViewer, RustDesk) at the request of an unknown caller."
        ],
        "what_to_do_if_affected": [
            "Immediately turn on 'Airplane Mode' and disconnect Wi-Fi to stop remote screen control.",
            "Dial 1930 immediately to freeze financial transfers.",
            "Uninstall any suspicious app in Android Safe Mode or perform a full factory reset of your smartphone to completely eliminate persistent background trojans."
        ]
    },
    {
        "id": "ADV-2026-IN03",
        "title": "Digital Arrest & Impersonation of CBI / ED / Police Video Extortion",
        "category": "Extortion / Social Engineering",
        "severity": "CRITICAL",
        "incident_date": "High-Frequency Targeted Threat",
        "threat_vector": "VoIP Calls · WhatsApp / Skype Video · Forged Arrest Warrants & Fake Police Stations",
        "target_audience": "Professionals, Senior Citizens, Business Owners",
        "cert_in_ref": "MHA & CERT-In Joint Public Alert / Supreme Court & CBI Warning",
        "legal_sections": "IT Act Section 66D, 419, 420, 384 (Extortion), 506 IPC",
        "summary": "Criminal syndicates posing as CBI, ED, Narcotics Control Bureau, or Mumbai Police call victims claiming parcels with drugs/passports were seized in their name, keeping them under fake 'Digital Arrest' on video to coerce massive fund transfers.",
        "modus_operandi": [
            "1. Victim receives an automated IVR call claiming to be FedEx/DHL or TRAI stating: 'Your parcel containing 5 passports and 140 grams of MDMA drugs has been seized by customs and your mobile connection will be blocked'.",
            "2. Call is forwarded to an accomplice impersonating a police inspector. The victim is made to join a Skype or WhatsApp video call.",
            "3. On camera, scammers sit in a studio staged exactly like a police station with police insignia, official emblems, and police uniforms.",
            "4. Scammers display forged arrest warrants signed by Supreme Court or CBI directors. They claim the victim is under 'Digital Arrest' and cannot hang up or tell family.",
            "5. The victim is coerced into transferring their lifetime savings into 'RBI Verification Escrow Accounts' for supposed forensic verification, promising refunds in 15 minutes that never arrive."
        ],
        "sample_indicators": [
            "Claims of 'Digital Arrest' — a non-existent legal concept in Indian jurisprudence",
            "Police or CBI demanding money transfers to 'Secret Verification Accounts'",
            "Demands to stay on video continuously and prohibition from consulting family or lawyers",
            "WhatsApp profiles with CBI or Mumbai Police crest photos"
        ],
        "protection_steps": [
            "THERE IS NO CONCEPT OF 'DIGITAL ARREST' UNDER INDIAN LAW. No police officer, judge, or agency has legal authority to arrest anyone via video call.",
            "No government agency (CBI, ED, NIA, Customs, Police) conducts interrogations or accepts money verification over Skype or WhatsApp.",
            "Never panic. If an unknown caller threatens arrest over a package or Aadhaar misuse, disconnect immediately.",
            "Verify any genuine police inquiry directly by visiting your local police station in person."
        ],
        "what_to_do_if_affected": [
            "Disconnect the video call immediately. Do NOT transfer a single rupee.",
            "Immediately report to the National Cyber Crime Helpline by dialing 1930.",
            "File a complaint at https://cybercrime.gov.in under 'Impersonation / Extortion' and note down the caller's phone numbers and Skype IDs."
        ]
    },
    {
        "id": "ADV-2026-IN04",
        "title": "Income Tax Department Refund Phishing & Credential Theft Portal",
        "category": "Credential Harvesting",
        "severity": "HIGH",
        "incident_date": "Tax Season Peak Campaign",
        "threat_vector": "Phishing Emails · Spoofed Gov Domains · Fake NetBanking Gateway",
        "target_audience": "Salaried Taxpayers & Small Business Owners",
        "cert_in_ref": "Income Tax Department Public Advisory / CERT-In CIAD-2026-0027",
        "legal_sections": "IT Act Section 66C, 66D, 420 IPC",
        "summary": "Fraudulent emails claiming an Income Tax refund of ₹15,480 has been approved, directing taxpayers to a fake portal that harvests PAN, Aadhaar, NetBanking passwords, and bank account credentials.",
        "modus_operandi": [
            "1. Taxpayer receives an email from 'admin@incometax-refunds.in' or 'refund@incometaxgov.org' with subject: 'IT Department: Refund of INR 15,480 approved for PAN xxxxxxxx. Confirm account details'.",
            "2. Email states that the refund could not be credited due to an account number mismatch, urging the user to click within 48 hours to prevent forfeiture.",
            "3. The destination page is an exact replica of the Income Tax e-Filing login portal.",
            "4. Once the user enters their PAN, user password, and selects their bank, the portal prompts for NetBanking user ID, login password, transaction password, and profile password, followed by an immediate OTP request to empty the bank account."
        ],
        "sample_indicators": [
            "incometax-refunds.in",
            "incometaxgov.org",
            "efiling-incometaxindia-gov.in",
            "Sender domain lacking @incometax.gov.in official suffix"
        ],
        "protection_steps": [
            "The Income Tax Department NEVER sends emails asking for bank passwords, credit card numbers, or NetBanking credentials to disburse refunds.",
            "Tax refunds are credited directly into your pre-validated bank account through RTGS/NECS via the State Bank of India refund banker.",
            "Check your actual refund status ONLY on the authentic e-Filing portal: https://www.incometax.gov.in.",
            "Always forward suspected fake tax emails to webmanager@incometax.gov.in and incident@cert-in.org.in."
        ],
        "what_to_do_if_affected": [
            "Immediately log in to your official NetBanking and change your login and transaction passwords.",
            "Block your NetBanking access temporarily by contacting your bank helpline or through SMS.",
            "Call 1930 and file a complaint on https://cybercrime.gov.in."
        ]
    },
    {
        "id": "ADV-2026-IN05",
        "title": "Aadhaar AePS Biometric Cloning & Unauthorized Micro-ATM Cash Drain",
        "category": "Biometric Fraud / Financial",
        "severity": "HIGH",
        "incident_date": "Recurring Financial Exploit",
        "threat_vector": "Cloned Silicon Fingerprints · Land Registry Document Harvesting · AePS Micro-ATMs",
        "target_audience": "Bank Account Holders with Aadhaar-Linked Accounts",
        "cert_in_ref": "UIDAI Biometric Security Circular / Reserve Bank of India Advisory",
        "legal_sections": "Aadhaar Act Section 38/42, IT Act Section 66C, 420 IPC",
        "summary": "Criminals copy thumbprints from publicly accessible land registry deeds onto synthetic polymer/silicon molds, using them to withdraw money from Aadhaar-linked accounts at AePS micro-ATMs without requiring an OTP or debit card.",
        "modus_operandi": [
            "1. Scammers download public property registration deeds, sale deeds, or sub-registrar documents that contain scanned thumb impressions alongside Aadhaar numbers.",
            "2. Using photographic chemical etching or 3D printers, they create synthetic silicon/polymer fingerprints matching the victim's biometric ridges.",
            "3. Scammers operate in collusion with remote AePS business correspondents (BC agents) in other states.",
            "4. Using the fake fingerprint and victim's Aadhaar number on a biometric micro-ATM scanner, they withdraw maximum daily limits (₹10,000 per transaction) repeatedly.",
            "5. Victims only realize when SMS transaction debit alerts arrive on their phone."
        ],
        "sample_indicators": [
            "AePS debit SMS alerts from unfamiliar locations without ATM card usage",
            "Debits of round amounts (₹10,000, ₹5,000) labeled 'AePS Cash Withdrawal'",
            "Absence of 2-factor OTP messages prior to debit"
        ],
        "protection_steps": [
            "LOCK YOUR AADHAAR BIOMETRICS: Download the official mAadhaar mobile app or visit https://myaadhaar.uidai.gov.in, log in with Aadhaar OTP, and turn on 'Lock Biometrics'.",
            "When locked, no one (including you) can perform AePS withdrawals. You can temporarily unlock it for 10 minutes when you need to authenticate.",
            "Masked Aadhaar: Share only 'Masked Aadhaar' (showing only the last 4 digits) for hotel bookings or identity verification instead of full Aadhaar.",
            "Instruct your bank to disable AePS payment facility on your savings account if you do not regularly use micro-ATMs."
        ],
        "what_to_do_if_affected": [
            "Lock your Aadhaar biometrics immediately on mAadhaar app to prevent further withdrawals.",
            "Dial 1930 within 2 hours to raise a cyber dispute on the National Cyber Crime portal.",
            "Submit a formal written complaint with your bank manager disputing the AePS debit within 3 days for zero-liability fraud reversal under RBI guidelines."
        ]
    },
    {
        "id": "ADV-2026-IN06",
        "title": "Part-Time Work-From-Home / Telegram Hotel Review Task Scam",
        "category": "Investment / Social Engineering",
        "severity": "HIGH",
        "incident_date": "Active Daily Surge",
        "threat_vector": "WhatsApp / Telegram · Fake Merchant Tasks · High Yield Crypto Portals",
        "target_audience": "Job Seekers, Students, Homemakers, Freelancers",
        "cert_in_ref": "MHA Indian Cybercrime Coordination Centre (I4C) Bulletin",
        "legal_sections": "IT Act Section 66D, 420 IPC, Banning of Unregulated Deposit Schemes Act",
        "summary": "Victims receive unsolicited WhatsApp texts offering ₹2,000–₹5,000 daily to like YouTube videos or review Google Maps places. Small initial payouts build trust before victims are lured into Telegram groups demanding large deposits for fake crypto/prepaid tasks.",
        "modus_operandi": [
            "1. Victim receives WhatsApp message from foreign/spoofed numbers offering flexible part-time work reviewing hotels or YouTube clips.",
            "2. Scammers pay ₹150–₹500 for the first 3 simple tasks directly to victim's UPI account to establish absolute credibility.",
            "3. The victim is migrated to a private Telegram group managed by 'Task Receptionists' and 'Senior Mentors'.",
            "4. The group introduces 'Prepaid High-Return Tasks' where depositing ₹5,000 yields ₹7,000. Fake members in the group post fake bank credit screenshots celebrating large profits.",
            "5. After the victim deposits larger sums (₹50,000 to ₹10,00,000), withdrawals are locked. Scammers demand 30% more for 'TDS', 'security deposit', or 'system error' until the victim is completely drained."
        ],
        "sample_indicators": [
            "Unsolicited job offers over WhatsApp/Telegram from unknown HR managers",
            "Tasks requiring paying money upfront to receive commissions",
            "Telegram groups where participants celebrate instant returns",
            "Payments asked to be sent to personal savings accounts belonging to mule accounts"
        ],
        "protection_steps": [
            "Legitimate companies NEVER recruit via unsolicited WhatsApp/Telegram texts for rating or liking tasks.",
            "NO REAL JOB requires an employee to pay money upfront to receive a salary or commission. Any job requiring advance deposit is 100% fraud.",
            "Do not join unsolicited Telegram channels promising guaranteed returns on review tasks.",
            "Report and block the WhatsApp/Telegram profile immediately using in-app report functions."
        ],
        "what_to_do_if_affected": [
            "Stop sending money immediately. Fraudsters will never let you withdraw your funds regardless of what 'fees' you pay.",
            "Call 1930 immediately with all beneficiary UPI IDs and bank account details where you transferred funds.",
            "Export your Telegram and WhatsApp chat logs with screenshots as evidence for your cybercrime filing."
        ]
    },
    {
        "id": "ADV-2026-IN07",
        "title": "Enterprise Microsoft 365 Device Code Phishing & AiTM Session Hijack",
        "category": "Enterprise Cloud Phishing",
        "severity": "CRITICAL",
        "incident_date": "Active Enterprise Campaign",
        "threat_vector": "OAuth 2.0 Device Code · Adversary-in-the-Middle (AiTM) Proxies · Cloud Account Takeover",
        "target_audience": "Corporate Employees, IT Administrators, Corporate Executives",
        "cert_in_ref": "CERT-In CIAD-2026-0019 / CISA Warning on AiTM Phishing",
        "legal_sections": "IT Act Section 43, 66, 66B",
        "summary": "Sophisticated phishing using reverse proxy frameworks (Evilginx) and OAuth Device Code authorization flows to bypass traditional 2FA/MFA, stealing session cookies and hijacking corporate M365 and Google Workspace accounts.",
        "modus_operandi": [
            "1. Corporate employee receives a simulated notification: 'DocuSign: Q3 Financial Audit Sign-Off Required' or 'IT Helpdesk: Mandatory MFA Device Registration'.",
            "2. Link points to an Adversary-in-the-Middle (AiTM) reverse proxy server that transparently relays authentication requests between victim and real Microsoft/Google login servers.",
            "3. Employee enters username, password, and authenticates real-time push notification or SMS code on authenticator app.",
            "4. The reverse proxy intercepts the valid post-auth session cookie (ESTSAUTH, PRT token) and session bearer tokens.",
            "5. Attacker imports the stolen session cookie into their browser, bypassing MFA entirely and gaining full access to corporate emails, OneDrive documents, and SharePoint directories."
        ],
        "sample_indicators": [
            "login.microsoftonline.com-auth-portal.com",
            "onedrive-share-point.net",
            "Sign-in alerts from foreign IPs without prompt for second password reset",
            "Creation of unauthorized OAuth mailbox forwarding rules"
        ],
        "protection_steps": [
            "Enforce FIDO2 / WebAuthn hardware security keys (e.g. YubiKey) — FIDO2 tokens bind cryptographically to the exact URL and CANNOT be phished by reverse proxies.",
            "Configure Conditional Access policies restricting sign-in to Microsoft Entra / Intune compliant corporate managed devices.",
            "Disable OAuth Device Authorization Grant flows if not explicitly required by headless IoT devices.",
            "Audit Mailbox inbox rules regularly for silent external forwarding rules."
        ],
        "what_to_do_if_affected": [
            "Immediately click 'Revoke All Sessions' in Microsoft 365 Admin / Azure AD console.",
            "Reset passwords and invalidate all active OAuth refresh tokens for the compromised account.",
            "Inspect and remove any newly registered MFA devices or mailbox forwarding rules created by attackers."
        ]
    }
]

class ThreatAdvisoriesService:
    @staticmethod
    def get_all_advisories(
        category: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Filter and return the curated database of recent cyber threat advisories."""
        items = MAJOR_ADVISORIES

        if category and category.lower() != "all":
            cat_lower = category.lower()
            items = [a for a in items if cat_lower in a["category"].lower()]

        if severity and severity.lower() != "all":
            sev_upper = severity.upper()
            items = [a for a in items if a["severity"].upper() == sev_upper]

        if search:
            query = search.lower().strip()
            items = [
                a for a in items
                if query in a["title"].lower()
                or query in a["summary"].lower()
                or query in a["threat_vector"].lower()
                or any(query in step.lower() for step in a["protection_steps"])
                or any(query in ind.lower() for ind in a["sample_indicators"])
            ]

        return items

    @staticmethod
    def get_advisory_by_id(advisory_id: str) -> Optional[Dict[str, Any]]:
        for a in MAJOR_ADVISORIES:
            if a["id"].upper() == advisory_id.upper():
                return a
        return None

    @staticmethod
    def format_certin_complaint(
        reporter_name: str,
        reporter_email: str,
        reporter_phone: str,
        incident_type: str,
        suspect_details: str,
        incident_description: str,
        financial_loss: Optional[float] = None,
        transaction_id: Optional[str] = None,
        bank_name: Optional[str] = None,
        evidence_urls: Optional[List[str]] = None,
    ) -> str:
        """
        Format a formal complaint draft conforming to India CERT-In & National Cyber Crime
        Reporting Portal (cybercrime.gov.in / 1930) submission requirements.
        """
        now = datetime.now(timezone.utc)
        complaint_ref = f"GM-IN-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        
        financial_section = ""
        if financial_loss and financial_loss > 0:
            financial_section = (
                f"\nFINANCIAL TRANSACTION PARTICULARS (FOR 1930 CFCFRMS FREEZE):\n"
                f"  - Approximate Defrauded Amount: ₹{financial_loss:,.2f}\n"
                f"  - Beneficiary / Suspect UPI / Transaction ID: {transaction_id or 'Not yet identified'}\n"
                f"  - Debited Bank / Payment Service: {bank_name or 'Under bank dispute verification'}\n"
            )

        evidence_section = ""
        if evidence_urls:
            evidence_section = "\nATTACHED TECHNICAL INDICATORS (IOCs):\n" + "\n".join([f"  - {u}" for u in evidence_urls])

        draft = (
            f"======================================================================\n"
            f"OFFICIAL CYBERCRIME & CERT-IN INCIDENT REPORT DRAFT\n"
            f"Reference Tracking ID: {complaint_ref}\n"
            f"Timestamp: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"Target Portals: https://cybercrime.gov.in | incident@cert-in.org.in | Helpline 1930\n"
            f"======================================================================\n\n"
            f"1. COMPLAINANT / REPORTING ENTITY DETAILS:\n"
            f"  - Full Name: {reporter_name}\n"
            f"  - Contact Email: {reporter_email}\n"
            f"  - Verified Phone: {reporter_phone or 'Provided during submission'}\n\n"
            f"2. INCIDENT CLASSIFICATION:\n"
            f"  - Primary Threat Category: {incident_type}\n"
            f"  - Suspect Identifiers (Number/Sender/Email): {suspect_details}\n"
            f"{financial_section}\n"
            f"3. INCIDENT NARRATIVE & MODUS OPERANDI:\n"
            f"{incident_description.strip()}\n"
            f"{evidence_section}\n\n"
            f"4. REQUESTED LAW ENFORCEMENT & CERT-IN ACTIONS:\n"
            f"  [x] Block and blacklist suspect domains / sender IDs at telecom & DNS levels.\n"
            f"  [x] Immediate coordination with National Cyber Crime Reporting Portal (1930 / I4C).\n"
            f"  [x] Issue preventative advisory to safeguard public consumers and organizations.\n\n"
            f"--- END OF OFFICIAL REPORT DRAFT (Generated by MailGuard Security Platform) ---"
        )
        return draft
