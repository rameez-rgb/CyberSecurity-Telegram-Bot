import requests


def lookup_ip(ip):
    url = f"http://ip-api.com/json/{ip}"

    try:
        response = requests.get(url, timeout=10)
        data = response.json()

        if data["status"] != "success":
            return None

        return {
            "ip": data["query"],
            "country": data["country"],
            "region": data["regionName"],
            "city": data["city"],
            "isp": data["isp"],
            "org": data["org"],
            "timezone": data["timezone"],
            "lat": data["lat"],
            "lon": data["lon"],
        }

    except Exception:
        return None