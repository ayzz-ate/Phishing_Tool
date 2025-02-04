import os
import requests
from dotenv import load_dotenv

load_dotenv()

class IPQS:
    def __init__(self, api_key):
        self.api_key = api_key

    def malicious_url_scanner_api(self, input_url):
        import urllib.parse
        encoded_url = urllib.parse.quote(input_url)
        api_url = f"https://www.ipqualityscore.com/api/json/url/{self.api_key}/{encoded_url}"
        response = requests.get(api_url)
        if response.status_code == 200:
            result = response.json()
            if result.get("phishing", False):
                return 1
            else:
                return -1
        return 0