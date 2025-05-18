from config import CRITICAL_PORTS

def detect_sensitive_ports(df):
    df["targets_critical_port"] = df["port"].isin(CRITICAL_PORTS)
    return df