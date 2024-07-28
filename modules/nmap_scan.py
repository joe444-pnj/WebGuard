import nmap

def scan_ports(target_url):
    nm = nmap.PortScanner()
    nm.scan(target_url)
    
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports.append({
                        "host": host,
                        "port": port,
                        "name": nm[host][proto][port]['name'],
                        "product": nm[host][proto][port]['product'],
                        "version": nm[host][proto][port]['version'],
                        "extrainfo": nm[host][proto][port]['extrainfo'],
                        "vulnerable": False  # Default to not vulnerable
                    })
    return open_ports

def scan_vulns(target_url):
    nm = nmap.PortScanner()
    nm.scan(target_url, arguments='--script vuln')
    
    vuln_report = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port]['state'] == 'open':
                    script_results = nm[host][proto][port].get('script')
                    if script_results:
                        vuln_report.append({
                            "host": host,
                            "port": port,
                            "name": nm[host][proto][port]['name'],
                            "vulns": script_results,
                            "vulnerable": True  # Mark as vulnerable
                        })
    return vuln_report
