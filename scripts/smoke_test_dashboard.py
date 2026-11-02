"""One-off Playwright smoke test of the Streamlit dashboard: log in,
check the overview loads, visit the Phishing Detector page and run a
check. Not part of the delivered project — just a dev-time sanity check."""
import sys
import time

from playwright.sync_api import sync_playwright


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))

        print("Loading dashboard...")
        page.goto("http://localhost:8501", timeout=20000)
        page.wait_for_timeout(2500)
        page.screenshot(path="/tmp/screenshot_1_login.png")

        print("Logging in...")
        # Streamlit text inputs: find by label text
        page.get_by_label("Username", exact=True).first.fill("admin")
        page.get_by_label("Password", exact=False).first.fill("SentinelAI123")
        page.get_by_role("button", name="Log in").click()
        page.wait_for_timeout(3000)
        page.screenshot(path="/tmp/screenshot_2_overview.png")

        body_text = page.inner_text("body")
        if "Security Overview" not in body_text:
            print("FAIL: overview page did not render after login")
            print(body_text[:500])
            sys.exit(1)
        print("PASS: overview page rendered after login")

        print("Navigating to Phishing Detector page...")
        page.get_by_role("link", name="Phishing Detector").click()
        page.wait_for_timeout(2500)
        page.screenshot(path="/tmp/screenshot_3_phishing.png")

        body_text = page.inner_text("body")
        if "Phishing & Malicious URL Detector" not in body_text:
            print("FAIL: phishing page did not render")
            sys.exit(1)
        print("PASS: phishing page rendered")

        if errors:
            print("JS ERRORS DETECTED:", errors)
        else:
            print("No JS errors detected.")

        browser.close()


if __name__ == "__main__":
    main()
