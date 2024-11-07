from flask import Flask, request, jsonify
import requests
from flask_cors import CORS
import spacy
from datetime import datetime
import os

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Load spaCy model
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    spacy.cli.download("en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")

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

def extract_cve_details(cve_json):
    """Extract primary CVE details from the JSON response."""
    base_info = {
        "CVE ID": get_safe_value(cve_json, ["cveMetadata", "cveId"]),
        "Published Date": get_safe_value(cve_json, ["cveMetadata", "datePublished"]),
        "Description": get_safe_value(cve_json, ["containers", "cna", "descriptions", 0, "value"]),
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
    return base_info

def generate_advanced_analysis(description, cve_details):
    """Generate detailed advanced analysis for the CVE."""
    analysis = {}

    # Vulnerability Summary
    analysis["Vulnerability Summary"] = (
        f"{cve_details['CVE ID']} is a vulnerability that allows unauthorized actions such as {description}. "
        "It is identified by a CVSS score of {0}, which suggests a {1} risk level."
        .format(cve_details.get("CVSS Score", "N/A"), cve_details.get("Attack Complexity", "N/A"))
    )

    # Technical Impact Analysis
    analysis["Technical Impact Analysis"] = (
        "This vulnerability impacts the {0} component by allowing attackers to {1}. "
        "As a result, this can lead to confidentiality, integrity, or availability issues."
        .format(cve_details.get("CVE ID", "N/A"), description)
    )

    # Exploitation Potential
    analysis["Exploitation Potential"] = (
        "The vulnerability has an attack vector of {0}, meaning it can be exploited {1}. "
        "The attack complexity is {2}, and {3} privileges are required."
        .format(
            cve_details.get("Attack Vector", "Unknown"),
            "remotely" if cve_details.get("Attack Vector") == "NETWORK" else "locally",
            cve_details.get("Attack Complexity", "Unknown"),
            cve_details.get("Privileges Required", "Unknown")
        )
    )

    # Mitigation Steps
    analysis["Mitigation Steps"] = (
        "To mitigate this vulnerability, it is recommended to apply patches as per the vendor guidelines. "
        "Other recommended steps include monitoring network traffic, enforcing strong access controls, "
        "and conducting regular security audits."
    )

    # Risk Assessment
    analysis["Risk Assessment"] = (
        "This vulnerability poses a significant risk due to {0} and the potential impact on {1}. "
        "Organizations are advised to apply the necessary patches and mitigation steps to reduce exposure."
        .format(cve_details.get("Attack Complexity", "Unknown"), "confidentiality, integrity, and availability")
    )

    return analysis

@app.route('/get_cve_info', methods=['GET'])
def get_cve_info():
    cve_id = request.args.get('cve_id')
    if not cve_id:
        return jsonify({"error": "Please provide a valid CVE ID"}), 400

    # Fetch CVE data from the external CVE API
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    response = requests.get(url)

    if response.status_code == 200:
        cve_json = response.json()
        cve_details = extract_cve_details(cve_json)

        # Generate advanced analysis based on description and details
        description = cve_details.get("Description", "N/A")
        advanced_analysis = generate_advanced_analysis(description, cve_details)

        # Include advanced analysis in the response
        cve_details["Advanced Analysis"] = advanced_analysis

        return jsonify(cve_details)
    else:
        return jsonify({"error": f"Failed to fetch CVE data, status code: {response.status_code}"}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))  
    app.run(host='0.0.0.0', port=port, debug=True)
