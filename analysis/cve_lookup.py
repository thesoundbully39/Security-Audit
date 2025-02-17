# file: analysis/cve_lookup.py

import requests
import time
import urllib.parse  # For URL encoding

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_cves_for_model(model_str, nvd_api_key):
    """
    Query the NVD API for CVEs related to a given model string.
    Handles API errors, including 404, rate limits, and malformed requests.
    """

    # URL Encode the model string
    encoded_model_str = urllib.parse.quote(model_str)

    params = {
        "keywordSearch": model_str,  # No need to encode in params dict
        "resultsPerPage": 20
    }
    headers = {
        "apiKey": nvd_api_key
    }

    # Debugging: Print request details
    print(f"\n[DEBUG] Querying NVD API:")
    print(f"  URL: {NVD_CVE_URL}")
    print(f"  Params: {params}")
    print(f"  Headers: {headers}")

    try:
        response = requests.get(NVD_CVE_URL, params=params, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            cve_ids = [vuln.get("cve", {}).get("id") for vuln in vulnerabilities if "cve" in vuln]
            print(f"  Found {len(cve_ids)} CVEs for: {model_str}")
            return cve_ids

        elif response.status_code == 404:
            print(f"[WARNING] NVD API returned 404 for query: {model_str} (Encoded: {encoded_model_str})")
            return []

        elif response.status_code == 403:
            print("[ERROR] NVD API access forbidden. Check your API key.")
            return []

        elif response.status_code == 429:
            print("[WARNING] Rate limit exceeded. Sleeping for 5 seconds...")
            time.sleep(5)
            return get_cves_for_model(model_str, nvd_api_key)

        else:
            print(f"[ERROR] Unexpected API response ({response.status_code}): {response.text}")
            return []

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] NVD API request failed: {e}")
        return []

    time.sleep(1)  # Small delay to prevent rate-limiting
