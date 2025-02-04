import requests
import urllib.parse

def check_phishing_virustotal(api_key, input_url): #VirusTotal API’ye HTTP isteği yapar.
    api_url = "https://www.virustotal.com/api/v3/urls"
    encoded_url = urllib.parse.quote(input_url)
    payload = f"url={encoded_url}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded"
    }
    response = requests.post(api_url, headers=headers, data=payload) #VirusTotal API’sine bağlanarak URL’nin kötü amaçlı olup olmadığını kontrol eder.
    if response.status_code == 200:
        data = response.json()
        analysis_id = data.get("data", {}).get("id")
        if analysis_id:
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers)
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json() #Gelen veriyi JSON formatında işler ve risk seviyesini belirler.
                stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
                if stats.get("malicious", 0) > 0 or stats.get("spam", 0) > 0:
                    return 1
                elif stats.get("undetected", 0) > 0:
                    return 0
                else:
                    return -1
    return 0