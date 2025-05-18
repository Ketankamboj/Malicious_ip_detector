import pandas as pd

def load_data(filepath):
    df = pd.read_csv(filepath)
    # Preprocess: Drop NA IPs, normalize ports
    df = df.dropna(subset=["source_ip"])
    df["port"] = df["port"].fillna(0).astype(int)
    return df