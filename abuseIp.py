import os
import requests
from dotenv import load_dotenv

load_dotenv()
#AbuseIPDB API’sinden gelen verileri işler ve IP’nin geçmişte zararlı faaliyetlerde bulunup bulunmadığını inceler.


def check_url_in_abuseipdb(raw_url):
    api_key = os.getenv("ABUSEIP_API_KEY")
    api_url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "url": raw_url,
        "maxAgeInDays": "90"
    }
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    response = requests.get(api_url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        if data.get("data", {}).get("isWhitelisted", False):
            return -1, data
        else:
            return 1, data
    return 0, None