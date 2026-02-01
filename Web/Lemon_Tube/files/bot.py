import time
import os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

# Configuration
TARGET_URL = os.environ.get('TARGET_URL', "http://127.0.0.1:5005/guestbook")
LOGIN_URL = os.environ.get('LOGIN_URL', "http://127.0.0.1:5005/admin/login")
DOMAIN = os.environ.get('DOMAIN', "127.0.0.1")

# RATE LIMITING: How often the bot visits (in seconds)
# Increased to prevent DoS-like behavior from repeated XSS execution
VISIT_INTERVAL = int(os.environ.get('VISIT_INTERVAL', 60))  # Default: 60 seconds

# Maximum time to wait for page/XSS execution
PAGE_TIMEOUT = int(os.environ.get('PAGE_TIMEOUT', 10))


def get_driver():
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")
    
    # Disable features that could cause issues (but allow external requests for webhooks)
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-plugins")
    chrome_options.add_argument("--disable-sync")
    
    service = Service("/usr/bin/chromedriver")
    chrome_options.set_capability('goog:loggingPrefs', {'browser': 'ALL'})
    
    driver = webdriver.Chrome(service=service, options=chrome_options)
    # Set page load timeout to prevent hanging
    driver.set_page_load_timeout(PAGE_TIMEOUT)
    return driver

def visit_guestbook():
    print("[Bot] Starting visit cycle...")
    driver = None
    try:
        driver = get_driver()
        
        # Login
        driver.get(LOGIN_URL)
        print(f"[Bot] Logging in at {LOGIN_URL}...")
        driver.find_element("name", "username").send_keys("admin")
        driver.find_element("name", "password").send_keys("password123")
        driver.find_element("tag name", "button").click()
        print("[Bot] Login submitted.")
        
        time.sleep(2)
        
        cookies = driver.get_cookies()
        print(f"[Bot] Current cookies: {cookies}")

        # Visit guestbook
        print(f"[Bot] Navigating to {TARGET_URL}")
        driver.get(TARGET_URL)
        
        # Wait for XSS to execute (limited time)
        time.sleep(PAGE_TIMEOUT)
        
        print(f"[Bot] Visit complete. Title: {driver.title}")
        
        for entry in driver.get_log('browser'):
            print(f"[Bot] Browser Log: {entry}")

    except Exception as e:
        print(f"[Bot] Error during visit: {e}")
    finally:
        if driver:
            try:
                driver.quit()
            except Exception as e:
                print(f"[Bot] Error closing driver: {e}")

def bot_loop():
    print("[Bot] Bot loop started. Waiting for triggers...")
    while True:
        try:
            # Check for trigger file
            if os.path.exists('/tmp/bot_trigger'):
                print("[Bot] Trigger detected! Visiting guestbook...")
                
                # Remove trigger file to prevent loop
                try:
                    os.remove('/tmp/bot_trigger')
                except Exception as e:
                    print(f"[Bot] Error removing trigger file: {e}")
                
                visit_guestbook()
            else:
                # Sleep briefly to avoid busy waiting
                time.sleep(5)
                
        except Exception as e:
            print(f"[Bot] Critical error in loop: {e}")
            time.sleep(5)

if __name__ == "__main__":
    print("[Bot] Selenium Admin Bot started.")
    print(f"[Bot] Visit interval: {VISIT_INTERVAL}s, Page timeout: {PAGE_TIMEOUT}s")
    time.sleep(5) 
    bot_loop()

