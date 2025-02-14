# your_project/analysis/iot_detection.py

HIGH_RISK_PORTS = [23, 21, 80, 445, 8080, 8888]

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

def find_iot_devices(all_devices):
    iot_devs = []
    for dev in all_devices:
        vendor = dev.get("Vendor", "Unknown").lower()
        os_name = dev.get("OS", "Unknown").lower()
        if any(v.lower() in vendor for v in COMMON_IOT_VENDORS):
            iot_devs.append(dev)
        elif any(v.lower() in os_name for v in COMMON_IOT_VENDORS):
            iot_devs.append(dev)
    return iot_devs

def assess_iot_risk(device):
    """Return a simple risk rating if we find high-risk ports or known issues."""
    risk_level = "LOW"
    for p in device["Ports"]:
        p_id = p.split()[0]  # e.g., '23'
        try:
            port_num = int(p_id)
            if port_num in HIGH_RISK_PORTS:
                risk_level = "HIGH"
        except ValueError:
            pass
    return risk_level

def correlate_iot_alerts(iot_devices, alerts):
    iot_ips = {d["IP"] for d in iot_devices}
    for a in alerts:
        a["iot_related"] = (a.get("src_ip") in iot_ips or a.get("dest_ip") in iot_ips)
