# file: analysis/cve_lookup.py

import requests

# For the new NVD API 2.0, see: 
# https://nvd.nist.gov/developers/v2

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_cves_for_model(model_str, nvd_api_key):
    """
    Query the NVD API v2 with 'model_str' to retrieve relevant CVEs.
    We'll do a naive approach: passing model_str as a 'keywordSearch'.
    Return a list of CVE IDs. Possibly truncated by resultsPerPage.

    Example usage:
      cves = get_cves_for_model("TP-Link Archer C7", "YOUR_NVD_API_KEY")
    """
    # Basic GET request with keywordSearch
    params = {
        "keywordSearch": model_str,
        "resultsPerPage": 20  # adjust as needed
    }
    headers = {
        "apiKey": nvd_api_key,
        # Some users need a custom User-Agent
        # "User-Agent": "MySecurityAuditScript/1.0"
    }

    try:
        r = requests.get(NVD_CVE_URL, params=params, headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            # The 2.0 response has a structure with "vulnerabilities"
            # Each item has a "cve" -> "id"
            cve_ids = []
            vulnerabilities = data.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                cve_id = vuln.get("cve", {}).get("id")
                if cve_id:
                    cve_ids.append(cve_id)
            return cve_ids
        else:
            print(f"Warning: NVD API returned {r.status_code}")
            return []
    except Exception as e:
        print(f"Error contacting NVD: {e}")
        return []
