import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import secrets
import argparse

def generate_nonce():
    return secrets.token_urlsafe(16)

def fetch_webpage(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching the webpage: {e}")
        return None

def parse_html(html_content):
    return BeautifulSoup(html_content, 'html.parser')

def extract_resources(soup, base_url):
    resources = {
        'script-src': set(),
        'style-src': set(),
        'img-src': set(),
        'font-src': set(),
        'connect-src': set(),
    }

    base_domain = urlparse(base_url).netloc

    for tag, attr, directive in [
        ('script', 'src', 'script-src'),
        ('link', 'href', 'style-src'),
        ('img', 'src', 'img-src'),
        ('link', 'href', 'font-src'),
    ]:
        for element in soup.find_all(tag, **{attr: True}):
            if tag == 'link' and element.get('rel')[0] not in ['stylesheet', 'font']:
                continue
            url = urljoin(base_url, element[attr])
            domain = get_domain(url)
            if domain:
                resources[directive].add(domain)

    resources['connect-src'].add(base_domain)

    return resources, base_domain

def get_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or None

def get_root_domain(domain):
    parts = domain.split('.')
    if len(parts) > 2:
        return '.'.join(parts[-2:])
    return domain

def group_domains(domains, base_domain):
    grouped = set()
    root_domain = get_root_domain(base_domain)
    for domain in domains:
        if domain in ["'self'", "https:"]:
            grouped.add(domain)
        elif domain.endswith(root_domain):
            if domain == base_domain:
                grouped.add(domain)
            grouped.add(f'*.{root_domain}')
        else:
            grouped.add(domain)
    return grouped

def generate_csp_header(resources, base_domain, report_uri=None):
    nonce = generate_nonce()
    csp_parts = []
    root_domain = get_root_domain(base_domain)
    
    # Special handling for script-src with nonce and strict-dynamic
    script_src = group_domains(resources['script-src'], base_domain)
    script_src_value = f"'nonce-{nonce}' 'strict-dynamic' https: 'unsafe-inline' {' '.join(script_src)}"
    csp_parts.append(f"script-src {script_src_value}")
    
    # Handle other directives
    for directive, domains in resources.items():
        if directive != 'script-src':  # We've already handled script-src
            domains.add("'self'")
            domains.add('https:')
            grouped_domains = group_domains(domains, base_domain)
            csp_parts.append(f"{directive} {' '.join(grouped_domains)}")
    
    # Add default directives
    default_directives = [
        f"default-src 'self' https: {base_domain} *.{root_domain}",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'self'",
        "upgrade-insecure-requests"
    ]
    
    csp_parts.extend(default_directives)
    
    # Add reporting directive if a report URI is provided
    if report_uri:
        csp_parts.append(f"report-uri {report_uri}")
        csp_parts.append(f"report-to csp-endpoint")
    
    return '; '.join(csp_parts), nonce

def main():
    parser = argparse.ArgumentParser(description="Generate a Content Security Policy with optional violation reporting.")
    parser.add_argument("url", help="The URL of the website to analyze")
    parser.add_argument("--report-uri", help="The URI to send CSP violation reports to (optional)")
    args = parser.parse_args()

    html_content = fetch_webpage(args.url)
    
    if html_content:
        soup = parse_html(html_content)
        resources, base_domain = extract_resources(soup, args.url)
        csp_header, nonce = generate_csp_header(resources, base_domain, args.report_uri)
        
        print("\nSuggested Content Security Policy Header:")
        print(f"Content-Security-Policy: {csp_header}")
        
        if args.report_uri:
            print(f"\nReporting has been enabled. Violations will be reported to: {args.report_uri}")
            print("You may also want to add the following header to enable the Report-To API:")
            print(f"Report-To: {{'group':'csp-endpoint','max_age':10886400,'endpoints':[{{'url':'{args.report_uri}'}}]}}")
        else:
            print("\nNote: CSP violation reporting is not enabled. Use --report-uri to enable it.")
        
        print(f"\nNonce for this page load: {nonce}")
        print("\nNote: You need to add this nonce to all inline <script> tags in your HTML.")
        print("Example: <script nonce=\"" + nonce + "\">...</script>")
        
        print("\nImportant: This is a basic CSP header. Please review and adjust as needed for your specific security requirements.")
        print("Remember to generate a new nonce for each page load in your production environment.")
    else:
        print("Failed to analyze the website. Please check the URL and try again.")

if __name__ == "__main__":
    main()
