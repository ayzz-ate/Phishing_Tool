import os
import re
import requests
import socket

def generate_variations(domain): # URL'nin farklı versiyonlarını oluşturur
    parts = domain.split(".")
    if len(parts) < 2:
        return []
    domain_name, tld = parts[0], parts[1]
    variations = []
    variations.extend(swap_similar_characters(domain_name + "." + tld))
    variations.extend(duplicate_characters(domain_name, tld))
    variations.extend(adjacent_character_swap(domain_name, tld))
    variations.extend(missing_character(domain_name, tld))
    variations.extend(reverse_adjacent_characters(domain_name, tld))
    variations.extend(add_subdomain(domain_name, tld))
    variations.extend(change_tld(domain_name))
    variations.extend(add_extra_characters(domain_name, tld))
    variations.extend(homoglyph_characters(domain_name, tld))
    return variations

def swap_similar_characters(domain):
    similar_chars = {
        'a': ['à', 'á', 'â', 'ä', 'ã', 'å', 'α', 'а'],
        'b': ['ɓ', 'β', 'в'],
        'c': ['ç', 'ć', 'č', 'ċ', 'с'],
        'd': ['đ', 'ɗ', 'д'],
        'e': ['è', 'é', 'ê', 'ë', 'ε', 'е'],
        'f': ['ƒ'],
        'g': ['ĝ', 'ğ', 'ǧ', 'ġ', 'г'],
        'h': ['ħ', 'н'],
        'i': ['ì', 'í', 'î', 'ï', 'ι', 'і'],
        'j': ['ј'],
        'k': ['ķ', 'к'],
        'l': ['ł', '1', 'I', 'ⅼ'],
        'm': ['м'],
        'n': ['ñ', 'ń', 'η', 'п'],
        'o': ['ò', 'ó', 'ô', 'ö', 'õ', 'ο', 'о'],
        'p': ['þ', 'ρ', 'р'],
        'q': ['ԛ'],
        'r': ['ř', 'г'],
        's': ['ş', 'ś', 'š', 'ѕ'],
        't': ['ť', 'т'],
        'u': ['ù', 'ú', 'û', 'ü', 'υ', 'у'],
        'v': ['ν'],
        'w': ['ŵ'],
        'x': ['х'],
        'y': ['ý', 'ÿ', 'у'],
        'z': ['ž', 'ź', 'ż', 'ʐ'],
        '0': ['ο', 'О', '0'],
        '1': ['ⅼ', 'І'],
        '2': ['２'],
        '3': ['з'],
        '4': ['４'],
        '5': ['５'],
        '6': ['６'],
        '7': ['７'],
        '8': ['８'],
        '9': ['９'],
    }
    variations = []
    for i, char in enumerate(domain):
        if char in similar_chars:
            for sim_char in similar_chars[char]:
                new_domain = domain[:i] + sim_char + domain[i+1:]
                variations.append(new_domain)
    return variations

def duplicate_characters(domain_name, tld):
    variations = []
    for i in range(len(domain_name)):
        new_domain = domain_name[:i] + domain_name[i] + domain_name[i:] + "." + tld
        variations.append(new_domain)
    return variations

def adjacent_character_swap(domain_name, tld):
    variations = []
    for i in range(len(domain_name)-1):
        new_domain = domain_name[:i] + domain_name[i+1] + domain_name[i] + domain_name[i+2:] + "." + tld
        variations.append(new_domain)
    return variations

def missing_character(domain_name, tld):
    variations = []
    for i in range(len(domain_name)):
        new_domain = domain_name[:i] + domain_name[i+1:] + "." + tld
        variations.append(new_domain)
    return variations

def reverse_adjacent_characters(domain_name, tld):
    variations = []
    for i in range(len(domain_name)-1):
        new_domain = domain_name[:i] + domain_name[i+1] + domain_name[i] + domain_name[i+2:] + "." + tld
        variations.append(new_domain)
    return variations

def add_subdomain(domain_name, tld):
    subdomains = ["www", "login", "secure", "account"]
    variations = []
    for sub in subdomains:
        variations.append(f"{sub}.{domain_name}.{tld}")
    return variations

def change_tld(domain_name):
    tlds = ["com", "net", "org", "info", "co", "biz", "xyz", "club", "online", "site", "shop", "top", "pro", "tech", "click"]
    variations = []
    for tld in tlds:
        variations.append(f"{domain_name}.{tld}")
    return variations

def add_extra_characters(domain_name, tld):
    extra_chars = ["-", "1", "0"]
    variations = []
    for char in extra_chars:
        variations.append(f"{domain_name}{char}.{tld}")
        variations.append(f"{char}{domain_name}.{tld}")
    return variations

def homoglyph_characters(domain_name, tld):
    homoglyphs = {'o': 'ο', 'a': 'а', 'e': 'е'}
    variations = []
    for i, char in enumerate(domain_name):
        if char in homoglyphs:
            new_domain = domain_name[:i] + homoglyphs[char] + domain_name[i+1:] + "." + tld
            variations.append(new_domain)
    return variations

def check_domain(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        return response.status_code == 200
    except:
        try:
            response = requests.get(f"http://{domain}", timeout=5)
            return response.status_code == 200
        except:
            try:
                socket.gethostbyname(domain)
                return True
            except:
                return False

def check_phishing(url): #Google Safe Browsing ve VirusTotal API’sini kullanarak kontrol eder.
    variations = generate_variations(url)
    with open("suspectUrls.txt", "w") as file:
        for variation in variations:
            if check_domain(variation):
                file.write(variation + "\n")