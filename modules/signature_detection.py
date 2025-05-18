# modules/signature_detection.py
from config import THREAT_INTELLIGENCE_FEEDS
import requests
import pandas as pd

def check_blacklist(df):
    """Check IPs against threat intelligence feeds"""
    blacklist = set()
    
    # Load from local blacklist.txt if exists
    try:
        with open('data/blacklist.txt', 'r') as f:
            blacklist.update(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        pass
    
    # Load from online feeds
    for url in THREAT_INTELLIGENCE_FEEDS:
        try:
            response = requests.get(url, timeout=10)
            blacklist.update(response.text.splitlines())
        except Exception as e:
            print(f"Failed to load {url}: {str(e)}")
    
    # Mark blacklisted IPs
    df['is_blacklisted'] = df['source_ip'].isin(blacklist)
    return df