from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import requests
from urllib.parse import urlparse
import os
import time
from dotenv import load_dotenv  # Add this line to support loading .env file

app = Flask(__name__)
CORS(app)

# Load environment variables from .env file
load_dotenv()

# Load your VirusTotal API key securely from environment variables
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "ebbbee393b6a5caa7cc511f1cc5a1f5a75370f36722be1e3708c9c9d2c83601f")  # Replace with your key or load from .env

def unshorten_url(url):
    try:
        session = requests.Session()
        resp = session.head(url, allow_redirects=True, timeout=5)
        return resp.url
    except Exception as e:
        print(f"Error unshortening URL: {e}")
        return url

def is_phishing(url):
    reasons = []
    parsed = urlparse(url)

    if parsed.scheme == 'http':
        reasons.append("URL uses HTTP instead of HTTPS.")
    if '@' in url:
        reasons.append("URL contains '@' symbol.")
    if re.match(r'^http[s]?:\/\/\d+\.\d+\.\d+\.\d+', url):
        reasons.append("URL uses an IP address instead of a domain.")
    if len(url) > 75:
        reasons.append("URL is excessively long.")
    if url.count('.') > 3:
        reasons.append("URL has too many dots (subdomains).")
    if url.count('/') > 5:
        reasons.append("URL has too many slashes (deep path).")
    
    suspicious_keywords = ['login', 'verify', 'update', 'banking', 'secure', 'account', 'free', 'win']
    if any(word in url.lower() for word in suspicious_keywords):
        reasons.append("URL contains suspicious keywords.")

    shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'buff.ly', 'adf.ly']
    if any(short in parsed.netloc for short in shorteners):
        reasons.append("URL uses a known shortening service.")

    if not reasons:
        return {"result": "Safe", "reasons": []}
    elif len(reasons) <= 2:
        return {"result": "Suspicious", "reasons": reasons}
    else:
        return {"result": "Phishing", "reasons": reasons}

def check_virustotal(url):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        data = {"url": url}

        # Submit URL for scanning
        submit_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
        submit_response.raise_for_status()
        scan_id = submit_response.json()["data"]["id"]

        # Wait briefly and fetch the result
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        for _ in range(6):
            time.sleep(3)
            result_response = requests.get(analysis_url, headers=headers)
            result_response.raise_for_status()
            result_data = result_response.json()
            if result_data["data"]["attributes"]["status"] == "completed":
                stats = result_data["data"]["attributes"]["stats"]
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                return {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "raw_stats": stats
                }
        return {"error": "Timeout waiting for VirusTotal analysis."}
    except Exception as e:
        print(f"VirusTotal error: {e}")
        return {"error": str(e)}

@app.route('/')
def home():
    return "CyberAware Flask API is running!"

@app.route('/check', methods=['POST'])
def check_url():
    data = request.json
    url = data.get('url', '')

    expanded_url = unshorten_url(url)
    print(f"Original URL: {url}, Expanded URL: {expanded_url}")

    heuristics = is_phishing(expanded_url)
    vt_results = check_virustotal(expanded_url)

    return jsonify({
        "original_url": url,
        "expanded_url": expanded_url,
        "heuristic_result": heuristics["result"],
        "heuristic_reasons": heuristics["reasons"],
        "virustotal": vt_results
    })

if __name__ == '__main__':
    app.run(debug=True)
