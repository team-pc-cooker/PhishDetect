PhishDetect - Phishing URL Scanner

This is a basic Python project that checks if a URL is suspicious based on:

- Phishing-related keywords (login, verify, update)
- Suspicious domain endings (.tk, .ml, etc.)
- IP addresses instead of domain names
- Long and complex URL structures

How to run:
1. Install Python 3 on your phone or computer.
2. Save the main code in a file named app.py.
3. Open a terminal or Python editor.
4. Run the command: python app.py
5. Enter any URL to check it.

Example:
URL: http://secure-login.tk/account/verify
Output:
[!] This URL appears suspicious for the following reasons:
- Contains suspicious keywords
- Uses suspicious TLD
- URL is unusually long

Author: Gollapudi Sriram