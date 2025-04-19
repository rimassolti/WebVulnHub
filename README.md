# Web Vulnerability Scanner

A powerful tool for identifying common web vulnerabilities such as SQL injection, cross-site scripting (XSS), cross-site request forgery (CSRF), and more.

## About

This tool is designed to help security researchers and developers identify potential vulnerabilities in web applications. It includes features for detecting SQL injection, XSS, CSRF, and other common web vulnerabilities. The scanner also includes directory enumeration, subdomain enumeration, and version detection.

## Features

- **SQL Injection Detection**: Tests for common SQL injection vulnerabilities.
- **XSS Detection**: Identifies potential cross-site scripting vulnerabilities.
- **CSRF Detection**: Checks for the presence of CSRF tokens in forms.
- **Directory Enumeration**: Attempts to find common directories like `/admin`, `/login`, etc.
- **Subdomain Enumeration**: Tries to find common subdomains like `www`, `mail`, etc.
- **Version Detection**: Extracts version information from server headers.
- **HTML Injection Testing**: Tests for HTML injection vulnerabilities.
- **Multi-threading**: Speeds up the scanning process by using multiple threads.
- **Verbose Output**: Provides detailed output for debugging.

## Getting Started

### Requirements

- Python 3.x
- `requests` library
- `BeautifulSoup` library

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/rimassolti/WebVulnHub.git
   cd WebVulnHub
   ```

2. Install the required packages:
   ```bash
   pip install requests beautifulsoup4
   ```

### Usage

The tool can be run from the command line with the following arguments:

```bash
python WebVulnHub.py -u http://example.com
```

#### Command-Line Arguments

- `-u`, `--url`: The URL to scan (required).
- `-o`, `--output`: The output file for results (supports .txt and .json).
- `-s`, `--scan`: Scan level (1=quick, 2=full, 3=custom).
- `-a`, `--auth`: Basic authentication credentials (username and password).
- `-c`, `--cookie`: Session cookie.
- `-t`, `--threads`: Number of threads for concurrent scanning (default=5).
- `-v`, `--verbose`: Enable verbose output.

#### Example Usage

```bash
python WebVulnHub.py -u http://example.com -o scan_results.txt -t 10 -v
```

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Acknowledgments

- **Requests**: Used for making HTTP requests.
- **BeautifulSoup**: Used for parsing HTML responses.
- **Concurrent Futures**: Used for multi-threading.

## Disclaimer

This tool is for educational purposes only. Always ensure you have permission to scan a website, and avoid scanning production systems without proper authorization.

--- 

This `README.md` provides a clear and concise description of this tool, its features, and how to use it. 
