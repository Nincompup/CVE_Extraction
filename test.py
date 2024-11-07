from flask import Flask, request, jsonify
import requests
import pandas as pd
import spacy

import spacy.cli
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    spacy.cli.download("en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")

# Initialize the Flask app
app = Flask(__name__)

# Load the spaCy model for NER
nlp = spacy.load("en_core_web_sm")

# Helper function to safely retrieve nested values from JSON data
def get_safe_value(data, keys, default=""):
    for key in keys:
        if isinstance(data, list):
            if isinstance(key, int) and key < len(data):
                data = data[key]
            else:
                return default
        elif isinstance(data, dict):
            data = data.get(key, default)
        else:
            return default
    return data if data else default

# Helper function to extract structured fields from CVE description using NER and keyword matching
def extract_from_description(description_text):
    doc = nlp(description_text)
    extracted_data = {
        "Vulnerable Modules": [],
        "Attack Type": [],
        "Impact Keywords": [],
        "Affected Versions": [],
        "Related Hardware": [],
        "Exploitability": [],
        "Vulnerability Type": [],
        "Affected Components": [],
        "Detection Method": [],
        "Security Measures": [],
    }

    impact_keywords = ["denial of service", "remote code execution", "privilege escalation",
                       "data leakage", "information disclosure", "high CPU usage", "buffer overflow"]
    hardware_keywords = ["device", "router", "switch", "server", "network", "firewall"]
    version_identifiers = ["version", "prior to", "less than", "greater than"]
    exploit_keywords = ["exploit", "exploitable", "proof of concept", "exploit code"]
    detection_keywords = ["detected by", "discovered using", "identified with", "monitoring tool"]

    for ent in doc.ents:
        if ent.label_ in ["ORG", "PRODUCT"]:
            extracted_data["Vulnerable Modules"].append(ent.text)
        elif ent.label_ == "CARDINAL" or any(keyword in ent.text.lower() for keyword in version_identifiers):
            extracted_data["Affected Versions"].append(ent.text)
        elif ent.label_ == "EVENT":
            extracted_data["Attack Type"].append(ent.text)

    # Keyword matching for additional categories
    for token in doc:
        text = token.text.lower()
        if any(impact in text for impact in impact_keywords):
            extracted_data["Impact Keywords"].append(text)
        if any(hw in text for hw in hardware_keywords):
            extracted_data["Related Hardware"].append(text)
        if any(exploit in text for exploit in exploit_keywords):
            extracted_data["Exploitability"].append(text)
        if any(detect in text for detect in detection_keywords):
            extracted_data["Detection Method"].append(text)

    for key, values in extracted_data.items():
        extracted_data[key] = ', '.join(set(values))

    return extracted_data

# Helper function to extract detailed CVE information
def extract_cve_details(cve_json):
    base_info = {
        "CVE ID": get_safe_value(cve_json, ["cveMetadata", "cveId"]),
        "Published Date": get_safe_value(cve_json, ["cveMetadata", "datePublished"]),
        "Last Modified Date": get_safe_value(cve_json, ["cveMetadata", "dateUpdated"]),
        "Description": get_safe_value(cve_json, ["containers", "cna", "descriptions", 0, "value"]),
        "Vendor": get_safe_value(cve_json, ["containers", "cna", "affected", 0, "vendor"]),
        "Product": get_safe_value(cve_json, ["containers", "cna", "affected", 0, "product"]),
        "Platform": get_safe_value(cve_json, ["containers", "cna", "affected", 0, "platforms", 0]),
        "Solution": get_safe_value(cve_json, ["containers", "cna", "solutions", 0, "value"]),
        "Workaround": get_safe_value(cve_json, ["containers", "cna", "workarounds", 0, "value"]),
        "Mitigation Steps": get_safe_value(cve_json, ["containers", "cna", "mitigations", 0, "value"]),
        "Exploit Availability": get_safe_value(cve_json, ["containers", "cna", "exploitations", 0, "value"]),
        "Patch URL": get_safe_value(cve_json, ["containers", "cna", "solutions", 0, "url"]),
        "CVSS Score": get_safe_value(cve_json, ["containers", "cna", "metrics", 0, "cvssV3_0", "baseScore"]),
        "Attack Vector": get_safe_value(cve_json, ["containers", "cna", "metrics", 0, "cvssV3_0", "attackVector"]),
        "Attack Complexity": get_safe_value(cve_json, ["containers", "cna", "metrics", 0, "cvssV3_0", "attackComplexity"]),
        "Privileges Required": get_safe_value(cve_json, ["containers", "cna", "metrics", 0, "cvssV3_0", "privilegesRequired"]),
        "User Interaction": get_safe_value(cve_json, ["containers", "cna", "metrics", 0, "cvssV3_0", "userInteraction"]),
        "Scope": get_safe_value(cve_json, ["containers", "cna", "metrics", 0, "cvssV3_0", "scope"]),
        "Confidentiality Impact": get_safe_value(cve_json, ["containers", "cna", "metrics", 0, "cvssV3_0", "confidentialityImpact"]),
        "Integrity Impact": get_safe_value(cve_json, ["containers", "cna", "metrics", 0, "cvssV3_0", "integrityImpact"]),
        "Availability Impact": get_safe_value(cve_json, ["containers", "cna", "metrics", 0, "cvssV3_0", "availabilityImpact"]),
        "Reference Links": ', '.join([ref["url"] for ref in get_safe_value(cve_json, ["containers", "cna", "references"], []) if "url" in ref])
    }

    # Extract fields from the description using NER and keyword matching
    description = base_info["Description"]
    if description:
        ner_extracted = extract_from_description(description)
        base_info.update(ner_extracted)

    return base_info

# Flask endpoint to get CVE information
@app.route('/get_cve_info', methods=['GET'])
def get_cve_info():
    cve_id = request.args.get('cve_id')
    if not cve_id:
        return jsonify({"error": "Please provide a valid CVE ID"}), 400
    
    # Fetch CVE details from the CVE API
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    response = requests.get(url)
    
    if response.status_code == 200:
        cve_json = response.json()
        cve_details = extract_cve_details(cve_json)
        return jsonify(cve_details)
    else:
        return jsonify({"error": f"Failed to fetch CVE data, status code: {response.status_code}"}), 500

# Run the Flask app
if __name__ == '__main__':
    app.run(port=5000, debug=True)
