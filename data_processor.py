def extract_cve_info(cve_data):
    """Extracts key details from CVE API response."""
    try:
        # Navigate the response structure correctly
        cve_id = cve_data.get('id', 'N/A')
        description = cve_data.get('descriptions', [{'value': 'No description available'}])[0]['value']
        
        # Extract CVSS score and severity
        cvss_score = "N/A"
        severity = "N/A"
        if 'metrics' in cve_data and 'cvssMetricV31' in cve_data['metrics']:
            cvss_info = cve_data['metrics']['cvssMetricV31'][0]['cvssData']
            cvss_score = cvss_info.get('baseScore', 'N/A')
            severity = cvss_info.get('baseSeverity', 'N/A')

        # Extract references
        references = [ref['url'] for ref in cve_data.get('references', [])]

        return cve_id, description, cvss_score, severity, references

    except KeyError as e:
        print(f"⚠️ KeyError: Missing key in response - {e}")
        return None, None, None, None, None

    # Extract CVSS Score
    cvss_score = "N/A"
    if 'impact' in cve_data and 'baseMetricV3' in cve_data['impact']:
        cvss_score = cve_data['impact']['baseMetricV3']['cvssV3']['baseScore']
    
    # Extract MITRE ATT&CK Techniques (if any)
    attack_techniques = [
        ref['name'] for ref in cve_data['cve']['references']['reference_data'] 
        if 'attack.mitre.org' in ref['url']
    ]
    
    return cve_id, description, cvss_score, attack_techniques
