import argparse
import socket
from modules import sql_injection, xss, csrf, nmap_scan
from utils import session_handler, report_generator

def display_logo():
    logo = """
 __        __         _    ____                 
 \ \      / /__  _ __| | _|  _ \ __ _ _ __ ___  
  \ \ /\ / / _ \| '__| |/ / |_) / _` | '_ ` _ \ 
   \ V  V / (_) | |  |   <|  __/ (_| | | | | | |
    \_/\_/ \___/|_|  |_|\_\_|   \__,_|_| |_| |_|

        ____                                  
       / ___|___  _ __ ___  _ __   __ _ _ __  
      | |   / _ \| '_ ` _ \| '_ \ / _` | '_ \ 
      | |__| (_) | | | | | | |_) | (_| | | | |
       \____\___/|_| |_| |_| .__/ \__,_|_| |_|
                            |_|               
             Created by Moghazy
    """
    print(logo)

def main(target_url, output_file, detect_tech, port_scan, vuln_scan):
    display_logo()  # Display the logo at the start
    session = session_handler.create_session(target_url)
    vulnerabilities = []

    print("Running SQL Injection Scan...")
    sql_injection_results = sql_injection.scan(session, target_url)
    for result in sql_injection_results:
        result["vulnerable"] = True if "error" in result["response"].lower() else False
    vulnerabilities += sql_injection_results

    print("Running XSS Scan...")
    xss_results = xss.scan(session, target_url)
    for result in xss_results:
        result["vulnerable"] = True if "<script>" in result["response"].lower() else False
    vulnerabilities += xss_results

    print("Running CSRF Scan...")
    csrf_results = csrf.scan(session, target_url)
    for result in csrf_results:
        result["vulnerable"] = True if "csrf" in result["response"].lower() else False
    vulnerabilities += csrf_results

    open_ports = []
    nmap_vulns = []
    
    if port_scan:
        print("Running Nmap Port Scan...")
        open_ports = nmap_scan.scan_ports(target_url)
    
    if vuln_scan:
        print("Running Nmap Vulnerability Scan...")
        nmap_vulns = nmap_scan.scan_vulns(target_url)

    ip_address = socket.gethostbyname(target_url.replace("https://", "").replace("http://", "").split('/')[0])
    
    technologies = "Placeholder for technology detection" if not detect_tech else "Detected Technologies: Example CMS"
    # Implement actual technology detection here if needed

    print("Generating Report...")
    report_generator.generate_report(vulnerabilities, target_url, output_file, ip_address, technologies, open_ports, nmap_vulns)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WebGuard - Automated Web Vulnerability Scanner")
    parser.add_argument("target", help="Target URL of the web application to scan")
    parser.add_argument("-s", "--save", help="Filename to save the report as")
    parser.add_argument("-t", "--tech", action="store_true", help="Detect technologies used by the site")
    parser.add_argument("-p", "--port-scan", action="store_true", help="Run an Nmap port scan")
    parser.add_argument("-v", "--vuln-scan", action="store_true", help="Run an Nmap vulnerability scan")
    args = parser.parse_args()
    
    output_file = args.save if args.save else None

    main(args.target, output_file, args.tech, args.port_scan, args.vuln_scan)
