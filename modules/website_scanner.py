import requests
import time


def scan_website(url):

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    start = time.time()

    response = requests.get(
        url,
        timeout=10,
        allow_redirects=True
    )

    end = time.time()

    headers = response.headers

    result = {
        "url": response.url,
        "status": response.status_code,
        "server": headers.get("Server", "Unknown"),
        "https": response.url.startswith("https"),
        "response_time": round(end - start, 2),
        "security_headers": {
            "Content-Security-Policy":
                headers.get("Content-Security-Policy", "❌ Missing"),

            "Strict-Transport-Security":
                headers.get("Strict-Transport-Security", "❌ Missing"),

            "X-Frame-Options":
                headers.get("X-Frame-Options", "❌ Missing"),

            "X-Content-Type-Options":
                headers.get("X-Content-Type-Options", "❌ Missing"),

            "Referrer-Policy":
                headers.get("Referrer-Policy", "❌ Missing"),
        }
    }

    return result