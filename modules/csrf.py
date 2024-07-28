import requests

def scan(session, target_url):
    vulnerabilities = []
    response = session.get(target_url)
    if "csrf_token" not in response.text:
        vulnerabilities.append({
            "type": "CSRF",
            "url": target_url,
            "response": response.text
        })

    return vulnerabilities
