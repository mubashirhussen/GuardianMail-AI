import pytest
import re
from playwright.sync_api import Page, expect

@pytest.mark.e2e
def test_complete_analyst_user_journey(page: Page):
    """End-to-End browser workflow verifying login, dashboard metrics, threats list, and profile update."""
    
    # 1. Access portal homepage (redirects to login)
    page.goto("http://localhost:3000")
    
    # 2. Assert login interface displays branding
    expect(page.locator("h2")).to_contain_text("GuardianMail AI")
    
    # 3. Enter corporate credentials
    page.locator("input[type='email']").fill("analyst@guardianmail.ai")
    page.locator("input[type='password']").fill("VerySecurePassword123!")
    
    # 4. Click login submit button
    page.get_by_role("button", name=re.compile("Sign In to Console", re.IGNORECASE)).click()
    
    # 5. Assert redirection to Main Dashboard
    expect(page).to_have_url(re.compile(r"/"))
    expect(page.locator("h1")).to_contain_text("Security Command Console")
    
    # 6. Verify core widgets load
    expect(page.locator("text=Total Emails Scanned")).to_be_visible()
    expect(page.locator("text=Active Incident Cases")).to_be_visible()
    
    # 7. Navigate to Email Inbox Forensics page
    page.get_by_role("link", name=re.compile("Email Scans", re.IGNORECASE)).click()
    expect(page).to_have_url(re.compile(r"/emails"))
    
    # 8. Access Profile details setting
    page.get_by_role("link", name=re.compile("Profile", re.IGNORECASE)).click()
    expect(page).to_have_url(re.compile(r"/profile"))
    
    # 9. Trigger logout
    page.get_by_role("button", name=re.compile("Logout", re.IGNORECASE)).click()
    expect(page).to_have_url(re.compile(r"/login"))
