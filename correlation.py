import pandas as pd

MITRE_MAP = {
    "malware":    "T1204 - User Execution",
    "c2":         "T1071 - C2 Communication",
    "phishing":   "T1566 - Phishing",
    "ransomware": "T1486 - Data Encryption",
    "ddos":       "T1498 - Network Denial of Service",
    "threat_intel": "T1595 - Active Scanning"
}

def correlate(df):
    grouped = df.groupby("src_ip").agg(
        attack_count=("alert_type", "count"),
        top_severity=("severity", lambda x: x.mode()[0]),
        attack_types=("alert_type", lambda x: list(x.unique()))
    ).reset_index()

    grouped["mitre_technique"] = grouped["attack_types"].apply(
        lambda types: MITRE_MAP.get(types[0], "T1059 - Command Execution")
    )

    grouped["is_repeat_attacker"] = grouped["attack_count"] > 1
    grouped = grouped.sort_values("attack_count", ascending=False)
    return grouped