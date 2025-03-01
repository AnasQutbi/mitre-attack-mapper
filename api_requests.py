import requests  # For making API requests

def get_cve_details(cve_id):
    """Fetch CVE details from the NVD API."""
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    headers = {'User-Agent': 'MITRE-ATTACK-Mapper'}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        if 'result' in data and 'CVE_Items' in data['result']:
            return data['result']['CVE_Items'][0]
    return None
