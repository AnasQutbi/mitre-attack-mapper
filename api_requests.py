import requests

def get_cve_details(cve_id):
    """Fetch CVE details from the NVD API (v2)."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {'User-Agent': 'MITRE-ATTACK-Mapper'}
    
    response = requests.get(url, headers=headers)
    print(f"API Response Code: {response.status_code}")  # Debugging

    if response.status_code == 200:
        data = response.json()
        print(f"API Response Data: {data}")  # Print full response for debugging
        
        if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
            cve_info = data['vulnerabilities'][0]['cve']
            
            # Extract necessary details
            cve_id = cve_info.get('id', 'N/A')
            description = cve_info['descriptions'][0]['value'] if 'descriptions' in cve_info else "No description available"
            cvss_score = cve_info['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'] if 'metrics' in cve_info else "N/A"
            severity = cve_info['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'] if 'metrics' in cve_info else "N/A"
            references = [ref['url'] for ref in cve_info.get('references', [])]

            # Print extracted data
            print("\n🔹 CVE Details:")
            print(f"📌 CVE ID: {cve_id}")
            print(f"📝 Description: {description}")
            print(f"⚠️ CVSS Score: {cvss_score} ({severity})")

            if references:
                print("\n🔗 References:")
                for ref in references:
                    print(f"- {ref}")
            
            return cve_info

        else:
            print("⚠️ No CVE details found in response.")
    else:
        print(f"⚠️ API Error: {response.status_code} - {response.text}")  # Print error details
    
    return None
