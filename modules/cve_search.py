import requests
from config import NVD_API_KEY


def search_cve(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

    headers = {
        "apiKey": NVD_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code != 200:
            return None

        data = response.json()

        vulnerabilities = data.get("vulnerabilities")

        if not vulnerabilities:
            return None

        cve = vulnerabilities[0]["cve"]

        description = cve["descriptions"][0]["value"]

        metrics = cve.get("metrics", {})

        score = "N/A"
        severity = "N/A"

        if "cvssMetricV31" in metrics:
            metric = metrics["cvssMetricV31"][0]
            score = metric["cvssData"]["baseScore"]
            severity = metric["cvssData"]["baseSeverity"]

        elif "cvssMetricV30" in metrics:
            metric = metrics["cvssMetricV30"][0]
            score = metric["cvssData"]["baseScore"]
            severity = metric["cvssData"]["baseSeverity"]

        return {
            "id": cve["id"],
            "description": description,
            "score": score,
            "severity": severity,
            "published": cve["published"],
            "modified": cve["lastModified"]
        }

    except Exception:
        return None