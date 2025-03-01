def extract_cve_info(cve_data):
    """Extract necessary information from the CVE JSON response."""
    cve_id = cve_data['cve']['CVE_data_meta']['ID']
    description = cve_data['cve']['description']['description_data'][0]['value']
    
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
