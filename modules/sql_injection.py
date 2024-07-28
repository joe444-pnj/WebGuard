import requests

def scan(session, target_url):
    vulnerabilities = []
    payloads = ["'", "' OR 1=1 --", "' OR 'a'='a"]

    for payload in payloads:
        response = session.get(target_url + payload)
        if "error" in response.text or "mysql" in response.text:
            vulnerabilities.append({
                "type": "SQL Injection",
                "payload": payload,
                "url": target_url + payload,
                "response": response.text,
                "vulnerable": True
            })
        else:
            vulnerabilities.append({
                "type": "SQL Injection",
                "payload": payload,
                "url": target_url + payload,
                "response": response.text,
                "vulnerable": False
            })

    return vulnerabilities
