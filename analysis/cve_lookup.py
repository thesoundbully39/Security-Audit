# file: analysis/cve_lookup.py

import requests
import time
import urllib.parse  # <-- Import for URL encoding

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_cves_for_model(model_str, nvd_api_key):
    """
    Query the NVD API for CVEs related to a given model string.
    Handles API errors, including 404 responses.
    """
    # URL Encode the model_str to replace spaces with %20 and handle other characters
    encoded_model_str = urllib.parse.quote(model_str)

    params = {
        "keywordSearch": encoded_model_str,
        "resultsPerPage": 20
    }
    headers = {"apiKey": nvd_api_key}

    print(f"Querying NVD API: {NVD_CVE_URL}?keywordSearch={encoded_model_str}")  # Debugging line

    try:
        response = requests.get(NVD_CVE_URL, params=params, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            cve_ids = [vuln.get("cve", {}).get("id") for vuln in vulnerabilities if "cve" in vuln]
            return cve_ids
        
        elif response.status_code == 404:
            print(f"Warning: NVD API returned 404 for query: {model_str} (Encoded: {encoded_model_str})")
            return []

        elif response.status_code == 403:
            print("Error: NVD API access forbidden. Check your API key.")
            return []

        elif response.status_code == 429:
            print("Warning: Rate limit exceeded. Sleeping for 10 seconds...")
            time.sleep(10)
            return get_cves_for_model(model_str, nvd_api_key)

        else:
            print(f"Unexpected API response ({response.status_code}): {response.text}")
            return []

    except requests.exceptions.RequestException as e:
        print(f"Error contacting NVD API: {e}")
        return []
