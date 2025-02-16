import requests
import time
import urllib.parse

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_cves_for_model(model_str, nvd_api_key):
    """
    Query the NVD API for CVEs related to a given model string.
    Uses URL encoding and direct query strings.
    """

    # URL Encode the model string properly
    encoded_model_str = urllib.parse.quote(model_str)

    # Manually construct the query URL
    full_request_url = f"{NVD_CVE_URL}?keywordSearch={encoded_model_str}&resultsPerPage=20"

    # Use only API key in headers
    headers = {"apiKey": nvd_api_key}

    print(f"\n[DEBUG] Querying NVD API:")
    print(f"  URL: {full_request_url}")
    print(f"  Headers: {headers}")

    try:
        response = requests.get(full_request_url, headers=headers, timeout=15)

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
