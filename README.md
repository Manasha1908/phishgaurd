# PhishGuard — Phishing URL Risk Checker

## Overview
PhishGuard is a beginner-friendly Python cybersecurity awareness project. It checks the text of a URL for warning signs commonly associated with phishing, such as missing HTTPS, unusually long links, IP-address hosts, multiple hyphens, and suspicious words.

## Features
- Command-line interface
- Rule-based risk score and explanation
- No third-party dependencies
- Does not open or visit submitted URLs

## Requirements
- Python 3.8 or newer
- No external packages required

## Run
1. Download `phishguard.py`.
2. Open a terminal in the same folder.
3. Run:
   ```bash
   python phishguard.py
   ```
4. Enter a URL when prompted. Type `quit` to exit.

## Example test inputs
- `https://www.wikipedia.org`
- `http://192.0.2.1/login/verify`
- `http://secure-account-login.example.test/confirm`

These are examples for demonstrating the rules, not a definitive classification of real websites.

## How it works
The program parses the URL and adds points when it finds selected warning signs. It then labels the result as `LOWER RISK SIGNALS`, `CAUTION`, or `HIGH RISK`. Each result includes reasons so a user can understand the warning.

## Limitations and responsible use
- This is an educational prototype, not a production anti-phishing system.
- A low score does not mean a website is safe, and a high score does not prove a site is malicious.
- The program does not use machine learning, threat-intelligence feeds, DNS checks, or live website inspection.
- Do not enter passwords or other private information into suspicious websites.
- Use only for defensive education and awareness.
