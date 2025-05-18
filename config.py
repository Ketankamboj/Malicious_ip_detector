# config.py
API_KEYS = {
    "IPINFO": "772d3006ab083c"
}

THREAT_INTELLIGENCE_FEEDS = [
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "https://reputation.alienvault.com/reputation.data"
]

BLACKLIST_SOURCES = [
    "https://lists.blocklist.de/lists/all.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
]

# Thresholds
FREQUENCY_THRESHOLD = 100  # Requests/minute
CRITICAL_PORTS = [22, 3389, 80, 443]  # SSH, RDP, HTTP, HTTPS