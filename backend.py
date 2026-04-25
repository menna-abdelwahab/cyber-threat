import os
import requests
from dotenv import load_dotenv
from ai_engine import summarize, extract_iocs, score_risk, remediate

load_dotenv()

VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")
OTX_KEY        = os.getenv("OTX_KEY")
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_KEY")


def check_virustotal(ioc):
    """Check an IP, domain, or hash on VirusTotal."""
    try:
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        if len(ioc) in [32, 40, 64]:
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
        elif ioc.replace(".", "").isdigit():
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        else:
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        r = requests.get(url, headers=headers, timeout=10)
        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        return {"ioc": ioc, "malicious": malicious, "total": total,
                "verdict": "MALICIOUS" if malicious > 3 else "CLEAN"}
    except Exception as e:
        return {"ioc": ioc, "error": str(e), "verdict": "UNKNOWN"}


def check_otx(ip):
    """Check an IP on AlienVault OTX."""
    try:
        headers = {"X-OTX-API-KEY": OTX_KEY}
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        r = requests.get(url, headers=headers, timeout=10)
        data = r.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        return {"ip": ip, "pulse_count": pulse_count,
                "verdict": "SUSPICIOUS" if pulse_count > 0 else "CLEAN"}
    except Exception as e:
        return {"ip": ip, "error": str(e), "verdict": "UNKNOWN"}


def check_abuseipdb(ip):
    """Check an IP on AbuseIPDB."""
    try:
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers=headers, params=params, timeout=10)
        data = r.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        return {"ip": ip, "abuse_score": score,
                "verdict": "MALICIOUS" if score > 50 else "CLEAN"}
    except Exception as e:
        return {"ip": ip, "error": str(e), "verdict": "UNKNOWN"}


def enrich_iocs(iocs):
    """Run all IOCs through the 3 APIs."""
    enriched = {"ips": [], "domains": [], "hashes": []}
    for ip in iocs.get("ips", []):
        vt  = check_virustotal(ip)
        otx = check_otx(ip)
        abu = check_abuseipdb(ip)
        enriched["ips"].append({"value": ip, "virustotal": vt,
                                 "otx": otx, "abuseipdb": abu})
    for domain in iocs.get("domains", []):
        vt = check_virustotal(domain)
        enriched["domains"].append({"value": domain, "virustotal": vt})
    for h in iocs.get("hashes", []):
        vt = check_virustotal(h)
        enriched["hashes"].append({"value": h, "virustotal": vt})
    return enriched


def analyze_threat(text):
    """Main function — takes text, returns all results."""
    iocs = extract_iocs(text)
    enriched = enrich_iocs(iocs)
    return {
        "summary":     summarize(text),
        "iocs":        iocs,
        "iocs_enriched": enriched,
        "risk":        score_risk(text),
        "remediation": remediate(text)
    }