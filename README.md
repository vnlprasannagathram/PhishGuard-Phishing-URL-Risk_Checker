# PhishGuard — Phishing URL Risk Checker

## Project overview
PhishGuard is a beginner-friendly cybersecurity web application that checks a URL for common warning patterns and displays a rule-based risk category, score, reasons, and safety advice.

## Features
- Simple browser-based interface built with Streamlit
- URL format validation
- Checks for HTTP, IP-address hosts, `@`/user-info, punycode, many subdomains, suspicious terms, known URL shorteners, selected TLDs, long URLs, and multiple hyphens
- Explains which rules contributed to the score
- Does not open or visit the entered URL

## Important limitation
This is a rule-based educational demonstration, not a definitive phishing detector and not a trained machine-learning model. Its score is not a probability. A low-risk result does not guarantee safety, and legitimate websites may trigger warnings.

## Requirements
- Python 3.10 or newer recommended
- Visual Studio Code or another Python editor
- Internet connection for installing Streamlit

## Setup and run
1. Install Python from https://www.python.org/downloads/ and enable **Add Python to PATH** in the installer if shown.
2. Open this project folder in VS Code.
3. Open **Terminal → New Terminal**.
4. (Recommended) Create a virtual environment:
   - Windows: `python -m venv .venv`
   - PowerShell: `.\.venv\Scripts\Activate.ps1`
5. Install dependencies:
   `python -m pip install -r requirements.txt`
6. Start the website:
   `python -m streamlit run phishguard.py`
7. Streamlit will show a local URL, usually `http://localhost:8501`. Open it in your browser.

## Test examples
- `https://example.com` — expected to show few warning patterns (Low Risk).
- `http://192.168.1.1/login/verify` — expected to trigger several warning patterns.
These are examples for demonstrating the rules, not real-world safety verdicts.

## Project structure
- `phishguard.py` — complete application code in one Python file
- `requirements.txt` — Python package dependency
- `ProjectReport.docx` — project report

## Suggested GitHub upload
Create a repository named `PhishGuard`, upload the files, and include the repository URL in the final submission. Do not claim a GitHub link until you have created and uploaded the repository.
