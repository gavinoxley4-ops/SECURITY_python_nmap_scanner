**Python Nmap Vulnerability Scanner**

This is a little Python project I built to automate Nmap scans and make it easier to spot weak crypto (old TLS versions, bad ciphers, sketchy certificates, etc.). Instead of reading massive Nmap outputs every time, this script cleans it up and prints a readable report.
It’s mainly for learning python + useful for some CTF boxes I’ve been working on.

What it does
- Scans a target IP or subnet using Nmap
- Finds open ports and running services
- Checks versions (thanks to -sV)
- Runs SSL/TLS Nmap scripts (certificate + cipher suite checks)
- Parses the XML output so you don’t have to scroll through it manually
- Flags insecure crypto like:
- SSLv2 / SSLv3
- TLS 1.0 / 1.1
- RC4, NULL, EXPORT ciphers
- expired or self-signed certificates
- Prints everything in a clean, easy-to-read format
  
Basically, it’s a lightweight vulnerability scanner that focuses on crypto misconfigs and version info.

**How to run it**
- Install the Python dependencies: pip install python-nmap lxml
- Make sure Nmap is installed on your system
- Run the script: python3 scanner.py
- When it asks for a target, enter something like: 192.168.1.0/24
- It’ll do the scan, parse the XML output, and print a full report.

Example Output (roughly)

Host: 192.168.1.10
- Port 443/tcp : https (vOpenSSL 1.0.2)
- SSL/TLS Info: TLSv1.0 supported, RC4-MD5, Self-signed cert

Detected Crypto Weaknesses:
  - Weak protocol detected: TLSv1.0
  - Weak cipher suite present: RC4
  - Certificate is self-signed
