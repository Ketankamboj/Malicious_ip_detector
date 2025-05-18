# modules/geolocation.py
import requests
from config import API_KEYS

def get_ip_details(ip):
    """Get detailed threat intelligence using ipinfo.io API"""
    api_key = API_KEYS.get("IPINFO")
    
    if not api_key or api_key == "IPINFO":
        raise ValueError("IPINFO API key not configured in config.py")
    
    try:
        response = requests.get(
            f"https://ipinfo.io/{ip}/json?token={api_key}",
            timeout=10
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"IPInfo API Error: {str(e)}")
        return None

def enrich_ip_data(df):
    """Add threat intelligence data to DataFrame"""
    for ip in df["source_ip"].unique():
        details = get_ip_details(ip)
        
        if details:
            # Add relevant fields to DataFrame
            df.loc[df["source_ip"] == ip, "country"] = details.get("country", "Unknown")
            df.loc[df["source_ip"] == ip, "city"] = details.get("city", "Unknown")
            df.loc[df["source_ip"] == ip, "hostname"] = details.get("hostname", "")
            df.loc[df["source_ip"] == ip, "is_hosting"] = int("hosting" in details.get("org", "").lower())
            
    return df