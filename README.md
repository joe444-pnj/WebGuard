WebGuard is an automated web vulnerability scanner that can detect various vulnerabilities in a web application, including SQL Injection, XSS, and CSRF. It can also perform Nmap scans to find open ports and identify vulnerabilities.
Installation

    Clone the repository:
git clone https://github.com/joe444-pnj/WebGuard.git
cd WebGuard

Install dependencies:


    pip install -r requirements.txt

Command-Line Options

WebGuard offers several command-line options to customize your scans:

    -s, --save: Specify the filename to save the report.
    -t, --tech: Detect technologies used by the site (placeholder for now).
    -p, --port-scan: Run an Nmap port scan.
    -v, --vuln-scan: Run an Nmap vulnerability scan.

Basic Usage

To run a scan on a target URL:


python3 webguard.py <target_url>

Example:


python3 webguard.py https://example.com

Save Report with Custom Filename

To save the report with a custom filename:


python3 webguard.py <target_url> -s <filename>

Example:


python3 webguard.py https://example.com -s report.txt

Detect Technologies

To detect technologies used by the site (currently a placeholder):


python3 webguard.py <target_url> -t

Example:


python3 webguard.py https://example.com -t

Run Nmap Port Scan

To run an Nmap port scan:


python3 webguard.py <target_url> -p

Example:


python3 webguard.py https://example.com -p

Run Nmap Vulnerability Scan

To run an Nmap vulnerability scan:


python3 webguard.py <target_url> -v

Example:


python3 webguard.py https://example.com -v

Full Command

To run all options together:


python3 webguard.py <target_url> -s <filename> -t -p -v

Example:


python3 webguard.py https://example.com -s report.txt -t -p -v

Example Output


WebGuard Vulnerability Report

Target URL: https://www.facebook.com/
IP Address: 31.13.69.35
Technologies: Placeholder for technology detection

========================================

Vulnerability Scans:
☆ SQL Injection - Not Vulnerable
☆ XSS - Not Vulnerable
☆ CSRF - Not Vulnerable
----------------------------------------

Open Ports (Nmap Port Scan):
Port: 80, Service: http, Product: Apache, Version: 2.4.29, Info: Ubuntu
----------------------------------------

Nmap Vulnerability Scan:
Port: 80, Service: http, Vulnerabilities:
CVE-2021-XXXXX: Description of vulnerability
----------------------------------------

Report generated: data/reports/report.txt
