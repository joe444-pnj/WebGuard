import os
import re

def sanitize_filename(filename):
    return re.sub(r'[^a-zA-Z0-9_-]', '_', filename)

def generate_report(vulnerabilities, target_url, output_file, ip_address, technologies, open_ports, nmap_vulns):
    report_directory = os.path.join("data", "reports")
    if not os.path.exists(report_directory):
        os.makedirs(report_directory)
    
    if output_file:
        report_path = os.path.join(report_directory, output_file)
    else:
        base_name = sanitize_filename(target_url)
        report_path = os.path.join(report_directory, f"{base_name}_report.txt")
        index = 1
        while os.path.exists(report_path):
            report_path = os.path.join(report_directory, f"{base_name}_report{index}.txt")
            index += 1
    
    print(f"Saving report to {report_path}")

    with open(report_path, "w") as report_file:
        report_file.write(f"WebGuard Vulnerability Report\n")
        report_file.write(f"Target URL: {target_url}\n")
        report_file.write(f"IP Address: {ip_address}\n")
        report_file.write(f"Technologies: {technologies}\n")
        report_file.write(f"{'='*40}\n\n")
        
        if vulnerabilities:
            report_file.write("Vulnerability Scans:\n")
            for vulnerability in vulnerabilities:
                status = "Vulnerable" if vulnerability.get("vulnerable") else "Not Vulnerable"
                star = "★" if vulnerability.get("vulnerable") else "☆"
                report_file.write(f"{star} {vulnerability['type']} - {status}\n")
            report_file.write(f"{'-'*40}\n")
        else:
            report_file.write("No vulnerabilities found.\n")
        
        if open_ports:
            report_file.write("\nOpen Ports (Nmap Port Scan):\n")
            for port in open_ports:
                report_file.write(f"Port: {port['port']}, Service: {port['name']}, Product: {port['product']}, Version: {port['version']}, Info: {port['extrainfo']}\n")
            report_file.write(f"{'-'*40}\n")
        
        if nmap_vulns:
            report_file.write("\nNmap Vulnerability Scan:\n")
            for vuln in nmap_vulns:
                report_file.write(f"Port: {vuln['port']}, Service: {vuln['name']}, Vulnerabilities:\n")
                for key, value in vuln['vulns'].items():
                    report_file.write(f"{key}: {value}\n")
            report_file.write(f"{'-'*40}\n")
            
    print(f"Report generated: {report_path}")
