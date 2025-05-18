from config import FREQUENCY_THRESHOLD

def calculate_frequency(df):
    # Group by IP and count requests
    freq = df.groupby("source_ip").size().reset_index(name="request_count")
    df = df.merge(freq, on="source_ip")
    
    # Flag high-frequency IPs
    df["is_high_frequency"] = df["request_count"] > FREQUENCY_THRESHOLD
    return df