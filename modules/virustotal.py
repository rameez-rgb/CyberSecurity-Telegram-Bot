import requests
import base64
from config import VT_API_KEY


def scan_url(url):
    headers = {
        "x-apikey": VT_API_KEY
    }

    # Submit URL
    submit = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    if submit.status_code != 200:
        return None

    # URL identifier
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    result = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers=headers
    )

    if result.status_code != 200:
        return None

    data = result.json()["data"]["attributes"]["last_analysis_stats"]

    return {
        "malicious": data["malicious"],
        "suspicious": data["suspicious"],
        "harmless": data["harmless"],
    }