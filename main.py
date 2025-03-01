from api_requests import get_cve_details  # Import API request function
from data_processor import extract_cve_info  # Import data processing function
from tabulate import tabulate  # For displaying data in table format

def display_results(cve_id, description, cvss_score, attack_techniques):
    """Display the CVE details in a readable table format."""
    table = [
        ["CVE ID", cve_id],
        ["CVSS Score", cvss_score],
        ["Description", description[:100] + "..."]
    ]

    print(tabulate(table, headers=["Attribute", "Value"], tablefmt="grid"))

    if attack_techniques:
        print("\nMITRE ATT&CK Techniques:")
        for technique in attack_techniques:
            print(f"- {technique}")
    else:
        print("\nNo MITRE ATT&CK mappings found.")

def main():
    """Main function to get user input and fetch CVE details."""
    cve_id = input("Enter CVE ID (e.g., CVE-2023-1234): ").strip()
    cve_data = get_cve_details(cve_id)

    if cve_data:
        cve_id, description, cvss_score, severity, attack_techniques = extract_cve_info(cve_data)
        display_results(cve_id, description, cvss_score, attack_techniques)
    else:
        print("Error: CVE not found or API issue.")

if __name__ == "__main__":
    main()
    