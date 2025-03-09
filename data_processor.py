def extract_cve_info(cve_data):
    """Extracts key details from CVE API response."""
    try:
        # Extract CVE ID and description
        cve_id = cve_data.get('id', 'N/A')
        description = cve_data.get('descriptions', [{'value': 'No description available'}])[0]['value']
        
        # Extract CVSS score and severity
        cvss_score = "N/A"
        severity = "N/A"
        if 'metrics' in cve_data and 'cvssMetricV31' in cve_data['metrics']:
            cvss_info = cve_data['metrics']['cvssMetricV31'][0]['cvssData']
            cvss_score = cvss_info.get('baseScore', 'N/A')
            severity = cvss_info.get('baseSeverity', 'N/A')

        # Extract references (list of URLs)
        references = [ref['url'] for ref in cve_data.get('references', [])]

        # Extract MITRE ATT&CK Techniques (if any)
        attack_techniques = [
            ref['url'].split("/")[-1]  # Extract the last part of the URL as technique ID
            for ref in references if 'attack.mitre.org' in ref
        ]

        return cve_id, description, cvss_score, severity, attack_techniques

    except KeyError as e:
        print(f"⚠️ KeyError: Missing key in response - {e}")
        return None, None, None, None, None
