import requests
import argparse
from bs4 import BeautifulSoup
import re
import time
from urllib.parse import urljoin, urlparse
import os
import json
from concurrent.futures import ThreadPoolExecutor
import threading

# Define colors for output
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Initialize parser
parser = argparse.ArgumentParser(description='Advanced Web Vulnerability Scanner')
parser.add_argument('-u', '--url', required=True, help='URL to scan')
parser.add_argument('-o', '--output', help='Output file for results (supports .txt and .json)')
parser.add_argument('-s', '--scan', type=int, default=1, help='Scan level (1=quick, 2=full, 3=custom)')
parser.add_argument('-a', '--auth', nargs=2, metavar=('username', 'password'), help='Basic authentication credentials')
parser.add_argument('-c', '--cookie', help='Session cookie')
parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads for concurrent scanning')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

args = parser.parse_args()

# Define the URL
base_url = args.url
output_file = args.output
scan_level = args.scan
auth = args.auth
cookie = args.cookie
threads = args.threads
verbose = args.verbose

# Create output directory if needed
if output_file:
    directory = os.path.dirname(output_file)
    if not os.path.exists(directory):
        os.makedirs(directory)

# Session management
session = requests.Session()
if auth:
    session.auth = (auth[0], auth[1])
if cookie:
    session.cookies.set(cookie.split('=')[0], cookie.split('=')[1])

# Define SQL injection payloads
sql_payloads = [
    "'",
    "\"",
    " UNION SELECT * FROM users",
    " OR 1=1",
    " AND 1=1",
    " ORDER BY 1",
    " GROUP BY 1",
    " HAVING 1=1",
    " LIMIT 1",
    " OFFSET 1"
]

# Define XSS payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "</script><script>alert('XSS')</script>",
    "<img src='x' onerror='alert(\"XSS\")'>",
    "<input type='text' value='XSS' onfocus='alert(\"XSS\")'>",
    "<a href='javascript:alert(\"XSS\")'>Click me</a>",
    "<svg onload='alert(\"XSS\")'>",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>",
    "<object data='javascript:alert(\"XSS\")'></object>",
    "<embed src='javascript:alert(\"XSS\")'></embed>",
    "<form action='javascript:alert(\"XSS\")'></form>"
]

# Define common directories
common_dirs = [
    '/admin', '/login', '/register', '/user', '/password', '/reset', '/forgot', '/dashboard',
    '/profile', '/settings', '/logout', '/search', '/upload', '/download', '/api'
]

# Define common subdomains
common_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'forum', 'support', 'wiki', 'docs']

# Define HTML injection payloads
html_payloads = [
    "<strong>Test</strong>",
    "<em>Test</em>",
    "<mark>Test</mark>",
    "<small>Test</small>",
    "<del>Test</del>",
    "<ins>Test</ins>",
    "<sub>Test</sub>",
    "<sup>Test</sup>"
]

# Function to save results
def save_results(results, output_file):
    if output_file:
        if output_file.endswith('.txt'):
            with open(output_file, 'w') as f:
                f.write(results)
            print(f"{bcolors.OKGREEN}Results saved to {output_file}{bcolors.ENDC}")
        elif output_file.endswith('.json'):
            with open(output_file, 'w') as f:
                json.dump(results, indent=2, ensure_ascii=False, fp=f)
            print(f"{bcolors.OKGREEN}Results saved to {output_file}{bcolors.ENDC}")
        else:
            print(f"{bcolors.WARNING}Unsupported file format. Results will not be saved.{bcolors.ENDC}")
    else:
        print(f"{bcolors.WARNING}No output file specified, results will not be saved{bcolors.ENDC}")

# Function to detect SQL injection vulnerabilities
def detect_sql_injection(url):
    try:
        vulnerable = False
        for payload in sql_payloads:
            injection_url = url + payload
            response = session.get(injection_url, timeout=10)
            if "SQL" in response.text or "syntax" in response.text.lower():
                vulnerable = True
                break
        return vulnerable
    except Exception as e:
        if verbose:
            print(f"{bcolors.FAIL}Error in SQL injection test: {str(e)}{bcolors.ENDC}")
        return False

# Function to detect XSS vulnerabilities
def detect_xss(url):
    try:
        vulnerable = False
        for payload in xss_payloads:
            response = session.get(url, params={"name": payload}, timeout=10)
            if payload in response.text:
                vulnerable = True
                break
        return vulnerable
    except Exception as e:
        if verbose:
            print(f"{bcolors.FAIL}Error in XSS test: {str(e)}{bcolors.ENDC}")
        return False

# Function to detect CSRF vulnerabilities
def detect_csrf(url):
    try:
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        if not forms:
            return True  # No forms found, likely no CSRF protection
        has_csrf_token = False
        for form in forms:
            inputs = form.find_all('input')
            for inp in inputs:
                if inp.get('name') == 'csrf_token':
                    has_csrf_token = True
                    break
            if has_csrf_token:
                break
        return not has_csrf_token
    except Exception as e:
        if verbose:
            print(f"{bcolors.FAIL}Error in CSRF test: {str(e)}{bcolors.ENDC}")
        return True

# Function to enumerate directories
def enumerate_directories(base_url):
    try:
        found_dirs = []
        for dir in common_dirs:
            full_url = base_url + dir
            try:
                response = session.get(full_url, timeout=10)
                if response.status_code == 200:
                    found_dirs.append(full_url)
            except Exception as e:
                if verbose:
                    print(f"{bcolors.FAIL}Error checking {full_url}: {str(e)}{bcolors.ENDC}")
                continue
        return found_dirs
    except Exception as e:
        if verbose:
            print(f"{bcolors.FAIL}Error in directory enumeration: {str(e)}{bcolors.ENDC}")
        return []

# Function to enumerate subdomains
def enumerate_subdomains(base_url):
    try:
        subdomains = []
        parsed_url = urlparse(base_url)
        domain = parsed_url.netloc
        for sub in common_subdomains:
            full_url = f"http://{sub}.{domain}"
            try:
                response = session.get(full_url, timeout=10)
                if response.status_code == 200:
                    subdomains.append(full_url)
            except Exception as e:
                if verbose:
                    print(f"{bcolors.FAIL}Error checking {full_url}: {str(e)}{bcolors.ENDC}")
                continue
        return subdomains
    except Exception as e:
        if verbose:
            print(f"{bcolors.FAIL}Error in subdomain enumeration: {str(e)}{bcolors.ENDC}")
        return []

# Function to detect version information
def detect_version(url):
    try:
        response = session.get(url, timeout=10)
        headers = response.headers
        version = headers.get('X-Powered-By', headers.get('Server', 'Unknown'))
        return version
    except Exception as e:
        if verbose:
            print(f"{bcolors.FAIL}Error in version detection: {str(e)}{bcolors.ENDC}")
        return "Unknown"

# Function to test HTML injection
def test_html_injection(url):
    try:
        vulnerable = False
        for payload in html_payloads:
            response = session.get(url, params={"name": payload}, timeout=10)
            if payload in response.text:
                vulnerable = True
                break
        return vulnerable
    except Exception as e:
        if verbose:
            print(f"{bcolors.FAIL}Error in HTML injection test: {str(e)}{bcolors.ENDC}")
        return False

# Function to crawl the website
def crawl_website(base_url):
    try:
        visited_urls = set()
        to_crawl = [base_url]
        
        while to_crawl:
            url = to_crawl.pop(0)
            if url in visited_urls:
                continue
            visited_urls.add(url)
            
            try:
                response = session.get(url, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(base_url, link['href'])
                    if full_url not in visited_urls and urlparse(full_url).netloc == urlparse(base_url).netloc:
                        to_crawl.append(full_url)
            except Exception as e:
                if verbose:
                    print(f"{bcolors.FAIL}Error crawling {url}: {str(e)}{bcolors.ENDC}")
                continue
        return visited_urls
    except Exception as e:
        if verbose:
            print(f"{bcolors.FAIL}Error in website crawling: {str(e)}{bcolors.ENDC}")
        return set()

# Function to scan a single page
def scan_page(url):
    try:
        results = {}
        
        # SQL Injection
        sql_vuln = detect_sql_injection(url)
        results['sql_injection'] = sql_vuln
        
        # XSS
        xss_vuln = detect_xss(url)
        results['xss'] = xss_vuln
        
        # CSRF
        csrf_vuln = detect_csrf(url)
        results['csrf'] = csrf_vuln
        
        # HTML Injection
        html_vuln = test_html_injection(url)
        results['html_injection'] = html_vuln
        
        return results
    except Exception as e:
        if verbose:
            print(f"{bcolors.FAIL}Error scanning {url}: {str(e)}{bcolors.ENDC}")
        return {}

# Main scanning function
def scan_website():
    try:
        print(f"{bcolors.HEADER}Starting Web Vulnerability Scan...{bcolors.ENDC}")
        start_time = time.time()
        
        # Crawl the website
        crawled_urls = crawl_website(base_url)
        print(f"{bcolors.OKBLUE}Crawled {len(crawled_urls)} pages{bcolors.ENDC}")
        
        # Scan each page concurrently
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_page, url): url for url in crawled_urls}
            results = {}
            for future in futures:
                url = futures[future]
                try:
                    page_results = future.result()
                    results[url] = page_results
                except Exception as e:
                    if verbose:
                        print(f"{bcolors.FAIL}Error scanning {url}: {str(e)}{bcolors.ENDC}")
                    continue
        
        # Generate report
        report = {
            'target': base_url,
            'scan_level': scan_level,
            'timestamp': time.time(),
            'results': results
        }
        
        # Add additional information
        version = detect_version(base_url)
        dirs = enumerate_directories(base_url)
        subdomains = enumerate_subdomains(base_url)
        
        report['version'] = version
        report['directories'] = dirs
        report['subdomains'] = subdomains
        
        end_time = time.time()
        scan_time = end_time - start_time
        
        print(f"\n{bcolors.OKBLUE}Scan completed in {scan_time:.2f} seconds{bcolors.ENDC}")
        
        return report
    except Exception as e:
        if verbose:
            print(f"{bcolors.FAIL}Error in main scan: {str(e)}{bcolors.ENDC}")
        return {}

# Function to format the report
def format_report(report):
    try:
        formatted = ""
        
        # Basic information
        formatted += f"{bcolors.HEADER}# Web Vulnerability Scan Report{bcolors.ENDC}\n"
        formatted += f"{bcolors.OKBLUE}Target: {report['target']}{bcolors.ENDC}\n"
        formatted += f"{bcolors.OKBLUE}Scan Level: {report['scan_level']}{bcolors.ENDC}\n"
        formatted += f"{bcolors.OKBLUE}Version: {report['version']}{bcolors.ENDC}\n\n"
        
        # Vulnerabilities
        formatted += f"{bcolors.OKCYAN}## Vulnerabilities{bcolors.ENDC}\n"
        for url, results in report['results'].items():
            formatted += f"{bcolors.OKBLUE}URL: {url}{bcolors.ENDC}\n"
            if results.get('sql_injection'):
                formatted += f"{bcolors.FAIL}  - Vulnerable to SQL Injection{bcolors.ENDC}\n"
            if results.get('xss'):
                formatted += f"{bcolors.FAIL}  - Vulnerable to XSS{bcolors.ENDC}\n"
            if results.get('csrf'):
                formatted += f"{bcolors.FAIL}  - Vulnerable to CSRF{bcolors.ENDC}\n"
            if results.get('html_injection'):
                formatted += f"{bcolors.FAIL}  - Vulnerable to HTML Injection{bcolors.ENDC}\n"
            formatted += "\n"
        
        # Directories
        formatted += f"{bcolors.OKCYAN}## Directories{bcolors.ENDC}\n"
        if report['directories']:
            for dir in report['directories']:
                formatted += f"{bcolors.OKBLUE}{dir}{bcolors.ENDC}\n"
        else:
            formatted += f"{bcolors.OKGREEN}No common directories found{bcolors.ENDC}\n\n"
        
        # Subdomains
        formatted += f"{bcolors.OKCYAN}## Subdomains{bcolors.ENDC}\n"
        if report['subdomains']:
            for sub in report['subdomains']:
                formatted += f"{bcolors.OKBLUE}{sub}{bcolors.ENDC}\n"
        else:
            formatted += f"{bcolors.OKGREEN}No common subdomains found{bcolors.ENDC}\n\n"
        
        return formatted
    except Exception as e:
        if verbose:
            print(f"{bcolors.FAIL}Error formatting report: {str(e)}{bcolors.ENDC}")
        return ""

# Run the scan
if __name__ == "__main__":
    report = scan_website()
    formatted_report = format_report(report)
    
    if output_file:
        save_results(report, output_file)
    else:
        print(formatted_report)
