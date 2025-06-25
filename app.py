import re

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

def main():
    print("=== PhishDetect: Simple Phishing URL Scanner ===")
    url = input("Enter the URL to scan: ").strip()

    reasons = is_suspicious(url)
    if reasons:
        print("\n[!] This URL appears suspicious for the following reasons:")
        for reason in reasons:
            print(f"- {reason}")
    else:
        print("\n[✓] This URL seems safe based on basic checks.")

if __name__ == "__main__":
    main()