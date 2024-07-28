import requests

def scan(session, target_url):
    vulnerabilities = []
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]

    for payload in payloads:
        response = session.get(target_url, params={"q": payload})
        if payload in response.text:
            vulnerabilities.append({
                "type": "XSS",
                "payload": payload,
                "url": target_url,
                "response": response.text,
                "vulnerable": True
            })
        else:
            vulnerabilities.append({
                "type": "XSS",
                "payload": payload,
                "url": target_url,
                "response": response.text,
                "vulnerable": False
            })

    return vulnerabilities
