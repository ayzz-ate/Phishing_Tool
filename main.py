import os
import argparse
from dotenv import load_dotenv
from IPQS import IPQS
from abuseIp import check_url_in_abuseipdb
from fishAnimation import animate_fish
from googleSB import check_phishing_google_sb
from possiblePhishing import check_phishing as check_possible_phishing
from usom import check_phishing as check_usom_phishing
from virustotal import check_phishing_virustotal
from whois import get_domain_age_risk_point

def risk_evaluate(url_str):
    from urllib.parse import urlparse
    import re

    parsed_url = urlparse(url_str)
    if not parsed_url.scheme or not parsed_url.netloc:
        return "Geçersiz URL"

    risk_point = 0

    if parsed_url.scheme != "https":
        risk_point += 2
        print("Risk: HTTPS kullanılmıyor")

    if len(parsed_url.geturl()) > 50:
        risk_point += 2
        print("Risk: URL çok uzun")

    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly",
                  "ow.ly", "shorte.st", "adf.ly", "cli.re", "bl.ink", "v.gd", "qr.ae", "post.ly", "u.to",
                  "short.ie", "wp.me", "snipr.com", "po.st", "fic.kr", "tweez.me", "lnkd.in", "v.gd"]
    for shortener in shorteners:
        if shortener in parsed_url.netloc:
            risk_point += 3
            print("Risk: Kısaltılmış URL tespit edildi")
            break

    phishing_keys = ["secure", "login", "account", "signin", "update", "verify", "password", "aws",
                     "payment", "paypal", "confirm", "webscr", "restrict", "unusual", "activity", "suspend", "bank", "microsoft", "cloud"]
    for keyword in phishing_keys:
        if keyword in url_str:
            risk_point += 2
            print("Risk: Potansiyel phishing anahtar kelimesi tespit edildi")
            break

    suspicious_extensions = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".pw", ".top", ".club",
                             ".info", ".cc", ".ws", ".buzz", ".space", ".review", ".biz", ".trade", ".bid", ".loan", ".date", ".faith",
                             ".racing", ".freenom", ".partners", ".ventures", ".cheap", ".guru", ".domains", ".plumbing"]
    for ext in suspicious_extensions:
        if parsed_url.netloc.endswith(ext):
            risk_point += 3
            print("Risk: Şüpheli domain uzantısı tespit edildi")
            break

    from ipaddress import ip_address
    try:
        ip_address(parsed_url.netloc)
        risk_point += 3
        print("Risk: URL'de IP adresi tespit edildi")
    except ValueError:
        pass

    subdomains = parsed_url.netloc.split('.')
    if len(subdomains) > 3:
        risk_point += 2
        print("Risk: Aşırı alt domain tespit edildi")

    suspicious_char_pattern = r'[@!%&\^\*\(\)\{\}\[\]\\:;\"\'<>,\?\/~]'
    if re.search(suspicious_char_pattern, url_str):
        risk_point += 2
        print("Risk: Şüpheli karakterler tespit edildi")

    age_risk = get_domain_age_risk_point(parsed_url.netloc)
    risk_point += age_risk

    if risk_point >= 7:     # Şüpheli bulduğu URL'leri yazar.
    
        return f"Potansiyel phishing sitesi (Risk Puanı: {risk_point})"
    return f"Phishing sitesi değil (Risk Puanı: {risk_point})"

def clean_url(url):
    url = url.replace("http://", "").replace("https://", "").replace("www.", "")
    return url

def main():
    load_dotenv()
    ipqs_api_key = os.getenv("IPQS_API_KEY")
    virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")

    animate_fish()
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="URL to check", required=True)
    parser.add_argument("-s", "--suspect", action="store_true", help="Check for possible phishing, suspect URLs")
    args = parser.parse_args()

    cleaned_url = clean_url(args.url)
    print("URL kontrol ediliyor:", cleaned_url)

    if args.suspect:
        check_possible_phishing(cleaned_url)
        print("Şüpheli URL'ler suspectUrls.txt dosyasında kontrol edildi")

    ipqs = IPQS(ipqs_api_key)
    ipqs_result = ipqs.malicious_url_scanner_api(cleaned_url)
    if ipqs_result == 1:
        print("URL, IPQualityScore'da phishing olarak bulundu")
        return
    elif ipqs_result == -1:
        print("URL, IPQualityScore'da bulunamadı")

    usom_result, usom_details = check_usom_phishing(cleaned_url)
    if usom_result:
        print(f"URL, USOM'da phishing olarak bulundu: {usom_details}")
        with open("suspectUrls.txt", "a") as file:
            file.write(cleaned_url + "\n")
        print("Şüpheli URL suspectUrls.txt dosyasına kaydedildi.")
        return
    else:
        print("URL, USOM'da bulunamadı")

    google_sb_result, google_sb_details = check_phishing_google_sb(cleaned_url)
    if google_sb_result == 1:
        print(f"URL, Google Safe Browsing'de phishing olarak bulundu: {google_sb_details}")
        with open("suspectUrls.txt", "a") as file:
            file.write(cleaned_url + "\n")
        print("Şüpheli URL suspectUrls.txt dosyasına kaydedildi.")
        return
    elif google_sb_result == -1:
        print("URL, Google Safe Browsing'de bulunamadı")
    elif google_sb_result == 0:
        print("Google Safe Browsing sonucu belirsiz")

    vt_result = check_phishing_virustotal(virustotal_api_key, cleaned_url)
    if vt_result == 1:
        print("URL, VirusTotal'da phishing olarak bulundu")
        with open("suspectUrls.txt", "a") as file:
            file.write(cleaned_url + "\n")
        print("Şüpheli URL suspectUrls.txt dosyasına kaydedildi.")
        return

    elif vt_result == -1:
        print("URL, VirusTotal'da bulunamadı")

    abuse_ip_result, abuse_ip_details = check_url_in_abuseipdb(cleaned_url)
    if abuse_ip_result == 1:
        print(f"URL, AbuseIP'de phishing olarak bulundu: {abuse_ip_details}")
        return
    elif abuse_ip_result == -1:
        print("URL, AbuseIP'de güvenli bulundu")
    elif abuse_ip_result == 0:
        print("URL, AbuseIP'de bulunamadı")

    full_url = f"https://{cleaned_url}" if not args.url.startswith("http://") else f"http://{cleaned_url}"
    result = risk_evaluate(full_url)
    print("Sonuç:", result)

if __name__ == "__main__":
    main()