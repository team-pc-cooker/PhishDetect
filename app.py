import re
from datetime import datetime

# Suspicious patterns
suspicious_keywords = ['login', 'verify', 'update', 'secure', 'account', 'bank']
suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
ip_pattern = re.compile(r'https?://\d+\.\d+\.\d+\.\d+')

def is_suspicious(url):
    reasons = []

    if any(keyword in url.lower() for keyword in suspicious_keywords):
        reasons.append("Contains suspicious keywords")
    if any(url.endswith(tld) for tld in suspicious_tlds):
        reasons.append("Uses suspicious TLD")
    if len(url) > 75:
        reasons.append("URL is unusually long")
    if ip_pattern.match(url):
        reasons.append("Uses IP address instead of domain")

    return reasons

def log_to_file(url, reasons):
    with open("scan_report.txt", "a") as report:
        report.write(f"\nScan Time: {datetime.now()}\n")
        report.write(f"URL: {url}\n")
        if reasons:
            report.write("Status: SUSPICIOUS\nReasons:\n")
            for r in reasons:
                report.write(f"- {r}\n")
        else:
            report.write("Status: SAFE\n")
        report.write("-" * 40 + "\n")

def main():
    print("=== PhishDetect+: Phishing URL Scanner with Logging ===")
    url = input("Enter the URL to scan: ").strip()

    reasons = is_suspicious(url)
    if reasons:
        print("\n[!] This URL appears suspicious for the following reasons:")
        for reason in reasons:
            print(f"- {reason}")
    else:
        print("\n[✓] This URL seems safe based on basic checks.")

    log_to_file(url, reasons)
    print("\nScan result saved to 'scan_report.txt'.")

if __name__ == "__main__":
    main()
