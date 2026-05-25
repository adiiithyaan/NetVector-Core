import socket
import requests
from datetime import datetime

COMMON_PORTS = {
    21: "FTP (Plaintext credentials risk)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Insecure - Plaintext communication)",
    25: "SMTP (Mail Server)",
    80: "HTTP (Unencrypted Web Server)",
    110: "POP3 (Mail Server)",
    443: "HTTPS (Secure Web Server)",
    8080: "HTTP Alternate / Proxy"
}

class NetVectorCLI:
    def __init__(self, target):
        self.target = target
        self.target_ip = ""
        self.findings = []

    def resolve_target(self):
        """Resolves target hostname or URL down to its raw network IP address."""
        clean = self.target.replace("http://", "").replace("https://", "").split("/")[0]
        try:
            self.target_ip = socket.gethostbyname(clean)
            print(f"\033[94m[+]\033[0m Target Resolved: {clean} -> \033[92m{self.target_ip}\033[0m")
            return clean
        except socket.gaierror:
            print(f"\033[91m[-]\033[0m Error: Unable to resolve host '{clean}'")
            return None

    def scan_network_ports(self):
        """Probes standard network ports via direct TCP three-way handshakes."""
        print("\n" + "─"*65 + "\n[*] Phase 1: Probing Network Ports & Services\n" + "─"*65)
        for port, service in COMMON_PORTS.items():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            result = s.connect_ex((self.target_ip, port))
            
            if result == 0:
                print(f"  \033[93m[!]\033[0m Found Open Port: \033[1m{port}\033[0m ({service})")
                self.findings.append({
                    "id": f"NV-{len(self.findings)+1:02d}",
                    "category": "Network Exposure",
                    "threat": f"Open Port {port}",
                    "severity": "Low/Med",
                    "fix": "Close port if unused or restrict access via firewall."
                })
                
                
                try:
                    s.send(b"Hello\r\n")
                    banner = s.recv(512).decode(errors="ignore").strip()
                    if banner:
                        
                        sanitized_banner = "".join(ch for ch in banner if ord(ch) >= 32)[:40]
                        print(f"      └── \033[95mBanner Leaked:\033[0m {sanitized_banner}")
                        self.findings.append({
                            "id": f"NV-{len(self.findings)+1:02d}",
                            "category": "Info Leak",
                            "threat": f"Port {port} Banner",
                            "severity": "Info",
                            "fix": f"Mask version strings: {sanitized_banner}"
                        })
                except:
                    pass
            s.close()

    def audit_web_perimeter(self, clean_host):
        """Performs non-intrusive metadata header audits on exposed web layers."""
        print("\n" + "─"*65 + "\n[*] Phase 2: Inspecting Web Perimeter Configurations\n" + "─"*65)
        url = self.target if self.target.startswith(("http://", "https://")) else f"http://{clean_host}"
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            headers = response.headers

            if "Server" in headers:
                print(f"  \033[93m[!]\033[0m Software Banner Detected: {headers['Server']}")
                self.findings.append({
                    "id": f"NV-{len(self.findings)+1:02d}",
                    "category": "Info Leak",
                    "threat": "Server Header Exposure",
                    "severity": "Medium",
                    "fix": f"Modify server configuration to hide string: {headers['Server']}"
                })

            sec_headers = {
                "X-Frame-Options": ("Low", "Missing header. Risk of Clickjacking.", "Add 'X-Frame-Options: SAMEORIGIN' header."),
                "Content-Security-Policy": ("Medium", "Missing header. Higher risk of XSS injections.", "Implement a strong Content-Security-Policy."),
                "X-Content-Type-Options": ("Low", "Missing header. Vulnerable to MIME exploits.", "Add 'X-Content-Type-Options: nosniff' header.")
            }
            for sh, (sev, threat, fix) in sec_headers.items():
                if sh not in headers:
                    print(f"  \033[91m[!]\033[0m Missing Defense Header: {sh}")
                    self.findings.append({
                        "id": f"NV-{len(self.findings)+1:02d}",
                        "category": "Weak Config",
                        "threat": f"Missing {sh}",
                        "severity": sev,
                        "fix": fix
                    })
                    
        except requests.exceptions.RequestException as e:
            print(f"  \033[91m[-]\033[0m Web perimeter audit skipped: Connection failed ({e})")

    def render_summary_table(self, clean_host):
        """Draws a perfectly aligned, adaptive summary grid unaffected by string colors."""
        if not self.findings:
            print("\n" + "═"*75)
            print(f"  Target Scope : {clean_host} ({self.target_ip})")
            print("═"*75)
            print("\n  \033[92m[+]\033[0m Scan Complete: No common vulnerabilities or open vectors detected.")
            print("═"*75 + "\n")
            return

       
        sev_colors = {
            "High": "\033[91mHigh\033[0m",
            "Medium": "\033[91mMedium\033[0m",
            "Low/Med": "\033[93mLow/Med\033[0m",
            "Low": "\033[93mLow\033[0m",
            "Info": "\033[94mInfo\033[0m"
        }

        
        w_id = max(len("ID"), max(len(f['id']) for f in self.findings))
        w_cat = max(len("CATEGORY"), max(len(f['category']) for f in self.findings))
        w_threat = max(len("IDENTIFIED THREAT"), max(len(f['threat']) for f in self.findings))
        w_sev = max(len("SEVERITY"), max(len(f['severity']) for f in self.findings))
        w_fix = max(len("RECOMMENDED REMEDIATION"), max(len(f['fix']) for f in self.findings))

        
        top_border    = f"┌─{'─'*w_id}─┬─{'─'*w_cat}─┬─{'─'*w_threat}─┬─{'─'*w_sev}─┬─{'─'*w_fix}─┐"
        divider       = f"├─{'─'*w_id}─┼─{'─'*w_cat}─┼─{'─'*w_threat}─┼─{'─'*w_sev}─┼─{'─'*w_fix}─┤"
        bottom_border = f"└─{'─'*w_id}─┴─{'─'*w_cat}─┴─{'─'*w_threat}─┴─{'─'*w_sev}─┴─{'─'*w_fix}─┘"

       
        total_table_width = len(top_border)
        print("\n" + "═"*total_table_width)
        print(f" {'VULNERABILITY ASSESSMENT SUMMARY':^{total_table_width-2}}")
        print(f"  Target Scope : {clean_host} ({self.target_ip})")
        print(f"  Timestamp    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("═"*total_table_width)

        
        print(top_border)
        print(
            f"│ {'ID':<{w_id}} │ {'CATEGORY':<{w_cat}} │ {'IDENTIFIED THREAT':<{w_threat}} │ "
            f"{'SEVERITY':<{w_sev}} │ {'RECOMMENDED REMEDIATION':<{w_fix}} │"
        )
        print(divider)

        
        for f in self.findings:
            colored_sev = sev_colors.get(f['severity'], f['severity'])
            

            ansi_overhead = len(colored_sev) - len(f['severity'])
            target_sev_width = w_sev + ansi_overhead

            print(
                f"│ {f['id']:<{w_id}} │ {f['category']:<{w_cat}} │ {f['threat']:<{w_threat}} │ "
                f"{colored_sev:<{target_sev_width}} │ {f['fix']:<{w_fix}} │"
            )
            
        print(bottom_border)
        print(f" [*] Total footprint observations logged: {len(self.findings)}")
        print("═"*total_table_width + "\n")


if __name__ == "__main__":
    print("""
    ┌──────────────────────────────────────────────┐
    │             NetVector-Core v1.0              │
    │  Network Exposure & Vector Core Audit Module │
    └──────────────────────────────────────────────┘
    """)
    target_raw = input("Enter target domain or IP (e.g., scanme.nmap.org): ").strip()
    if target_raw:
        scanner = NetVectorCLI(target_raw)
        host = scanner.resolve_target()
        if host:
            scanner.scan_network_ports()
            scanner.audit_web_perimeter(host)
            scanner.render_summary_table(host)