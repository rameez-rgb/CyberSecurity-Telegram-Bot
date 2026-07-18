import requests
from config import NEWS_API_KEY


def get_news():

    url = (
        "https://newsapi.org/v2/everything"
        "?q=cybersecurity"
        "&language=en"
        "&sortBy=publishedAt"
        "&pageSize=5"
    )

    headers = {
        "X-Api-Key": NEWS_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return None

    articles = response.json()["articles"]

    return articles