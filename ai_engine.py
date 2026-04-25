import re
from transformers import pipeline

print("Loading AI models... please wait 30 seconds")
summarizer = pipeline("summarization", model="facebook/bart-large-cnn")
classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
print("Models ready!")


def summarize(text):
    """Returns a short summary of the threat report."""
    if len(text.split()) < 30:
        return text
    try:
        result = summarizer(text[:1024], max_length=80, min_length=20, do_sample=False)
        return result[0]["summary_text"]
    except Exception:
        return text[:200] + "..."


def extract_iocs(text):
    """Finds all IPs, domains, hashes, and CVEs in the text."""
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    domains = re.findall(
        r'\b(?:[a-z0-9-]+\.)+(?:com|net|org|ru|io|xyz|info|biz|co|uk|de|fr)\b',
        text, re.IGNORECASE)
    hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', text)
    cves = re.findall(r'CVE-\d{4}-\d+', text, re.IGNORECASE)
    return {
        "ips": list(set(ips)),
        "domains": list(set(domains)),
        "hashes": list(set(hashes)),
        "cves": list(set(cves))
    }


def score_risk(text):
    """Returns a risk score 1-10 and level."""
    try:
        labels = ["critical threat", "high threat", "medium threat", "low threat"]
        result = classifier(text[:512], candidate_labels=labels)
        top = result["labels"][0]
        score_map = {
            "critical threat": ("9/10", "CRITICAL"),
            "high threat": ("7/10", "HIGH"),
            "medium threat": ("5/10", "MEDIUM"),
            "low threat": ("2/10", "LOW"),
        }
        return {"score": score_map[top][0], "level": score_map[top][1]}
    except Exception:
        return {"score": "5/10", "level": "MEDIUM"}


def remediate(text):
    """Returns a list of remediation steps based on threat type."""
    try:
        labels = ["malware", "phishing", "ransomware", "ddos", "sql injection", "c2 communication"]
        result = classifier(text[:512], candidate_labels=labels)
        threat = result["labels"][0]
    except Exception:
        threat = "malware"

    remap = {
        "malware": [
            "Run a full antivirus scan immediately",
            "Isolate infected machines from the network",
            "Block all suspicious IPs on the firewall",
            "Update all endpoint protection software",
            "Check for persistence mechanisms (scheduled tasks, registry)"
        ],
        "phishing": [
            "Reset passwords for all affected accounts immediately",
            "Enable multi-factor authentication (MFA) on all accounts",
            "Block the phishing domain at DNS level",
            "Warn all users not to click suspicious links",
            "Check email gateway rules to block similar messages"
        ],
        "ransomware": [
            "Isolate ALL infected systems from the network immediately",
            "Do NOT pay the ransom — it does not guarantee recovery",
            "Restore systems from the last clean backup",
            "Patch the exploited vulnerability before reconnecting",
            "Report the incident to national cybersecurity authority"
        ],
        "ddos": [
            "Enable rate limiting on your firewall immediately",
            "Contact your ISP to filter upstream traffic",
            "Activate Cloudflare or similar DDoS protection service",
            "Block the attacking IP ranges on your router",
            "Scale up server capacity temporarily if possible"
        ],
        "sql injection": [
            "Take the vulnerable application offline immediately",
            "Sanitize all user inputs — never trust raw input",
            "Use parameterized queries in all database calls",
            "Update your web application firewall (WAF) rules",
            "Audit all database access logs for data exfiltration"
        ],
        "c2 communication": [
            "Block the C2 server IP and domain on the firewall",
            "Scan all machines for backdoors and RATs",
            "Rotate all credentials, API keys, and certificates",
            "Review all outbound traffic logs for last 30 days",
            "Reimage compromised machines from clean image"
        ]
    }
    return remap.get(threat, [
        "Monitor all systems closely",
        "Apply all latest security patches",
        "Review access logs carefully",
        "Contact your security team immediately"
    ])
