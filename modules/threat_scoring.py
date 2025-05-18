# modules/threat_scoring.py
from config import API_KEYS

def compute_threat_score(df):
    """Calculate comprehensive threat score using API data"""
    # Base scores
    df["threat_score"] = 0
    
    # Scoring rules
    df.loc[df["is_blacklisted"], "threat_score"] += 40
    df.loc[df["is_high_frequency"], "threat_score"] += 25
    df.loc[df["targets_critical_port"], "threat_score"] += 20
    df.loc[df["is_hosting"] == 1, "threat_score"] += 15
    
    # Country risk (example - customize based on your needs)
    high_risk_countries = ["RU", "CN", "KP", "IR"]
    df.loc[df["country"].isin(high_risk_countries), "threat_score"] += 20
    
    # Classify threat level
    df["threat_level"] = "Safe"
    df.loc[df["threat_score"] >= 70, "threat_level"] = "Critical"
    df.loc[(df["threat_score"] >= 40) & (df["threat_score"] < 70), "threat_level"] = "Warning"
    
    return df