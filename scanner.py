import nmap
from lxml import etree

class CryptoAnalyzer:
    """Detect weak crypto configs from Nmap script output."""

    WEAK_PROTOCOLS = ["SSLV2", "SSLV3", "TLSV1.0", "TLSV1.1"]
    WEAK_CIPHERS = ["EXPORT", "NULL", "RC4", "DES", "3DES", "MD5"]

    @staticmethod
    def analyze(ssl_output):
        findings = []

        if not ssl_output:
            return findings

        text = ssl_output.upper()

        # Protocol checks
        for proto in CryptoAnalyzer.WEAK_PROTOCOLS:
            if proto in text:
                findings.append(f"⚠ Weak protocol detected: {proto}")

        # Cipher checks
        for cipher in CryptoAnalyzer.WEAK_CIPHERS:
            if cipher in text:
                findings.append(f"⚠ Weak cipher suite present: {cipher}")

        # Certificate checks
        if "SELF-SIGNED" in text:
            findings.append("⚠ Certificate is self-signed")

        if "EXPIRED" in text:
            findings.append("⚠ Certificate is expired")

        return findings


class NmapScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()

    def run_scan(self, target):
        print(f"[+] Scanning target: {target}")
        self.scanner.scan(
            hosts=target,
            arguments="-sV --script ssl-cert,ssl-enum-ciphers -oX scan.xml"
        )

    def parse_results(self, xml_file="scan.xml"):
        print("[+] Parsing scan results...")

        tree = etree.parse(xml_file)
        root = tree.getroot()

        full_report = []

        for host in root.findall("host"):
            address = host.find("address").get("addr")

            host_report = {"host": address, "ports": []}

            ports = host.find("ports")
            if ports is None:
                continue

            for port in ports.findall("port"):
                portnum = port.get("portid")
                proto = port.get("protocol")

                service_tag = port.find("service")
                service = service_tag.get("name") if service_tag is not None else "unknown"
                version = service_tag.get("version") if service_tag is not None else "unknown"

                # Collect SSL script output
                ssl_output = ""
                for script in port.findall("script"):
                    if "ssl" in script.get("id").lower():
                        ssl_output += script.get("output", "") + "\n"

                crypto_issues = CryptoAnalyzer.analyze(ssl_output)

                host_report["ports"].append({
                    "port": portnum,
                    "protocol": proto,
                    "service": service,
                    "version": version,
                    "ssl_output": ssl_output.strip(),
                    "crypto_issues": crypto_issues
                })

            full_report.append(host_report)

        return full_report

    def print_report(self, report):
        print("\n====== NMAP VULNERABILITY REPORT ======\n")

        if not report:
            print("No hosts found.")
            return

        for host in report:
            print(f"Host: {host['host']}")
            print("------------------------------------")

            if not host["ports"]:
                print("  No open ports found.\n")
                continue

            for p in host["ports"]:
                print(f"  Port {p['port']}/{p['protocol']} → {p['service']} (v{p['version']})")

                if p["ssl_output"]:
                    print("    SSL/TLS Info:")
                    for line in p["ssl_output"].split("\n"):
                        print(f"      {line}")

                if p["crypto_issues"]:
                    print("    ⚠ Detected Crypto Weaknesses:")
                    for issue in p["crypto_issues"]:
                        print(f"      {issue}")

                print()

            print()

def main():
    target = input("Enter target/subnet (e.g., 192.168.1.0/24): ")

    scanner = NmapScanner()
    scanner.run_scan(target)

    results = scanner.parse_results()
    scanner.print_report(results)

if __name__ == "__main__":
    main()
