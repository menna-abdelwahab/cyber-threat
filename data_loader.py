import pandas as pd
import requests
from datetime import datetime

def load_simulated_data(filepath="alerts.csv"):
    df = pd.read_csv(filepath)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

def fetch_otx_data(api_key):
    try:
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        headers = {"X-OTX-API-KEY": api_key}
        r = requests.get(url, headers=headers, timeout=10)
        pulses = r.json().get("results", [])
        rows = []
        for p in pulses[:10]:
            rows.append({
                "timestamp": datetime.now(),
                "src_ip": "unknown",
                "dst_ip": "unknown",
                "alert_type": "threat_intel",
                "severity": "medium",
                "description": str(p.get("description", ""))[:200]
            })
        return pd.DataFrame(rows)
    except Exception as e:
        print(f"OTX failed: {e} — using CSV only")
        return pd.DataFrame()

def get_all_data(api_key=None):
    df_local = load_simulated_data()
    if api_key:
        df_otx = fetch_otx_data(api_key)
        df = pd.concat([df_local, df_otx], ignore_index=True)
    else:
        df = df_local
    df = df.dropna(subset=['description'])
    df = df.reset_index(drop=True)
    return df