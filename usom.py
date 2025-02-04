import requests

def normalize_url(url):
    url = url.strip().replace("http://", "").replace("https://", "").replace("www.", "")
    return url

def check_phishing(url):
    normalized_url = normalize_url(url)
    api_url = f"https://www.usom.gov.tr/api/address/index?q={normalized_url}"
    response = requests.get(api_url)
    if response.status_code == 200:
        data = response.json()
        for address in data.get("models", []):
            if normalize_url(address["url"]) == normalized_url:
                return True, [address]
        return False, data.get("models", [])
    return False, []