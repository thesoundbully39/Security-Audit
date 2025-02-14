# file: analysis/iot_detection.py

from .cve_lookup import get_cves_for_model

COMMON_IOT_VENDORS = [
    "Espressif",
    "Raspberry Pi",
    "Wyze",
    "Ring",
    "TP-Link",
    "D-Link",
    "Arlo",
    "Eufy",
    "Hue",
    "Google",
    "Amazon",
]

HIGH_RISK_PORTS = [23, 21, 80, 445, 8080, 8888]


def guess_model_string(device):
    """
    Construct a string for NVD 'keywordSearch'.
    We'll use device's Vendor + Hostname or OS as a guess.
    For example: 'TP-Link Archer C7'
    """
    vendor = device.get("Vendor", "").strip()
    os_name = device.get("OS", "").strip()
    hostname = device.get("Hostname", "").strip()

    # If vendor is known, use it, plus something from OS or Hostname
    if vendor.lower() in ["unknown", ""]:
        # fallback
        vendor = ""
    # We'll prefer Hostname if it's not 'Unknown':
    if hostname.lower() not in ["unknown", ""]:
        return f"{vendor} {hostname}".strip()
    # else fallback to OS
    if os_name.lower() not in ["unknown", ""]:
        return f"{vendor} {os_name}".strip()

    # If all unknown, return an empty string
    return vendor or ""


def find_iot_devices(all_devices, nvd_api_key):
    """
    Identify IoT devices by vendor/OS, then query NVD for CVEs based on guessed model string.
    """
    iot_devs = []
    for dev in all_devices:
        vendor = dev.get("Vendor", "Unknown").lower()
        os_name = dev.get("OS", "Unknown").lower()

        # if it matches known IoT brand or OS
        if any(v.lower() in vendor for v in COMMON_IOT_VENDORS) or \
           any(v.lower() in os_name for v in COMMON_IOT_VENDORS):

            # guess a model string
            model_str = guess_model_string(dev)
            cves = []
            if model_str:
                # call NVD
                cves = get_cves_for_model(model_str, nvd_api_key)
            dev["CVEs"] = cves
            iot_devs.append(dev)

    return iot_devs


def assess_iot_risk(device):
    """
    Return a simple risk rating if we find high-risk ports or known CVEs, etc.
    """
    risk_level = "LOW"
    for p in device.get("Ports", []):
        p_id = p.split()[0]
        try:
            p_num = int(p_id)
            if p_num in HIGH_RISK_PORTS:
                risk_level = "HIGH"
        except ValueError:
            pass

    cves = device.get("CVEs", [])
    if cves and risk_level == "LOW":
        risk_level = "MEDIUM"
    return risk_level


def correlate_iot_alerts(iot_devices, alerts):
    """
    Mark Suricata alerts if they involve an IoT device IP.
    """
    iot_ips = {d["IP"] for d in iot_devices}
    for a in alerts:
        a["iot_related"] = (a.get("src_ip") in iot_ips or a.get("dest_ip") in iot_ips)
