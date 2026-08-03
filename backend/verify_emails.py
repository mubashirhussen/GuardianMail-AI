import asyncio
import os
from pathlib import Path
from app.services.email_parser import EmailParserService
from app.services.threat_detector import ThreatDetectorService
from app.services.recommender import RecommendationService
from app.services.report_generator import ReportGeneratorService

async def main():
    # Paths to the sample emails
    base_dir = Path(__file__).resolve().parent.parent / "phishing-email-analyzer"
    phishing_path = base_dir / "phishing.eml"
    legitimate_path = base_dir / "legitimate.eml"

    print("\n" + "=" * 80)
    print("           GUARDIANMAIL AI - SAMPLE EMAIL THREAT VERIFICATION")
    print("=" * 80)

    for name, path in [("PHISHING EMAIL", phishing_path), ("LEGITIMATE EMAIL", legitimate_path)]:
        if not path.exists():
            print(f"\n[ERROR] Sample email file not found at: {path}")
            continue

        print(f"\n>>> Analyzing {name}: {path.name} ...")
        
        # Read raw bytes
        with open(path, "rb") as f:
            eml_bytes = f.read()

        # Parse MIME structure
        parsed = EmailParserService.parse_eml_bytes(eml_bytes)
        
        # Analyze threats (heuristics engine)
        analysis = await ThreatDetectorService.analyze_email(parsed)
        
        # Compile recommendations
        recommendations = RecommendationService.generate_recommendations(analysis)
        
        # Merge results for the report generator
        email_record = {
            "_id": "verification_mock_id",
            "subject": parsed["subject"],
            "from_address": parsed["from_address"],
            "date": parsed["date"] or "N/A",
            "analysis": analysis.model_dump(),
            "recommendations": recommendations.model_dump()
        }

        # Print report
        report_text = ReportGeneratorService.export_threat_report_text(email_record)
        print(report_text)
        print("-" * 80)

if __name__ == "__main__":
    asyncio.run(main())
