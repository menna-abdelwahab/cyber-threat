from transformers import pipeline, AutoTokenizer, AutoModelForTokenClassification

# Load models once (slow first time, fast after)
print("Loading AI models...")
summarizer = pipeline("summarization", model="sshleifer/distilbart-cnn-12-6")
tokenizer = AutoTokenizer.from_pretrained("dslim/bert-base-NER")
ner_model = AutoModelForTokenClassification.from_pretrained("dslim/bert-base-NER")
ner_pipeline = pipeline("ner", model=ner_model, tokenizer=tokenizer,
                         aggregation_strategy="simple")
print("Models ready!")

def summarize_threat(text):
    """Turn long alert text into 1 sentence"""
    if len(text) < 30:
        return text  # too short to summarize
    try:
        result = summarizer(text, max_length=50, min_length=10)[0]
        return result['summary_text']
    except:
        return text[:100] + "..."

def extract_iocs(text):
    """Find IPs, domains, and other indicators in text"""
    import re
    iocs = []
    # Regex patterns (fast, reliable)
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
    
    ips = re.findall(ip_pattern, text)
    domains = re.findall(domain_pattern, text)
    hashes = re.findall(hash_pattern, text)
    
    for ip in ips:
        iocs.append({"type": "IP", "value": ip})
    for d in domains:
        if not d.endswith('.csv') and '.' in d:
            iocs.append({"type": "DOMAIN", "value": d})
    for h in hashes:
        iocs.append({"type": "HASH", "value": h})
    return iocs

def score_risk(row):
    """Rule-based risk score 1-10"""
    score = 5  # default
    desc = str(row.get('description', '')).lower()
    sev = str(row.get('severity', '')).lower()
    
    if sev == 'critical': score = 9
    elif sev == 'high': score = 7
    elif sev == 'medium': score = 5
    elif sev == 'low': score = 2
    
    # Boost for dangerous keywords
    if any(k in desc for k in ['ransomware','remote code','rce']): score = min(10, score+2)
    if any(k in desc for k in ['c2','command and control']): score += 1
    
    if score >= 8: priority = "Critical"
    elif score >= 6: priority = "High"
    elif score >= 4: priority = "Medium"
    else: priority = "Low"
    
    return score, priority

def process_alerts(df):
    """Run all AI on the dataframe"""
    import pandas as pd
    results = []
    for _, row in df.iterrows():
        desc = str(row['description'])
        summary = summarize_threat(desc)
        iocs = extract_iocs(desc)
        risk_score, priority = score_risk(row)
        results.append({
            **row.to_dict(),
            'summary': summary,
            'iocs': str(iocs),
            'risk_score': risk_score,
            'priority': priority
        })
    return pd.DataFrame(results)