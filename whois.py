import os
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
#alan adı kayıt firması
def get_domain_age_risk_point(domain):
    api_key = os.getenv("WHOIS_API_KEY")
    api_url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={domain}&outputFormat=JSON"
    response = requests.get(api_url)
    if response.status_code == 200:
        data = response.json()
        created_date = data.get("WhoisRecord", {}).get("createdDate")
        if created_date: # kayıt tarihi
            created_date = datetime.strptime(created_date, "%Y-%m-%dT%H:%M:%SZ")
            days_since_registration = (datetime.now() - created_date).days # süresi
            if days_since_registration < 30:
                return 5
    return 0