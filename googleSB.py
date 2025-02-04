import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

def check_phishing_google_sb(url):
    api_key = os.getenv("GOOGLESB_API_KEY")
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "Cuneyt",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["WINDOWS"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    headers = {"Content-Type": "application/json"}
    response = requests.post(api_url, headers=headers, data=json.dumps(payload))
    if response.status_code == 200:
        if "matches" in response.text:
            return 1, response.json()
        else:
            return -1, None
    return 0, None