import requests
from bs4 import BeautifulSoup
import re
import csv
from time import sleep
import os
from urllib.parse import urljoin
import datetime
import random


def scrape_chipsets_org_vulnerabilities(max_pages=500):
    """
    Large-scale scraper for Chipsets.org that can handle hundreds of pages

    Args:
        max_pages: Maximum number of pages to process (default: 500)
    """
    base_url = "https://www.chipsets.org"
    starting_points = [
        "https://www.chipsets.org/vulnerabilities",
        "https://www.chipsets.org/chipsets",
        "https://www.chipsets.org/search?q=cellular",
        "https://www.chipsets.org/search?q=modem",
        "https://www.chipsets.org/search?q=baseband",
        "https://www.chipsets.org/search?q=qualcomm",
        "https://www.chipsets.org/search?q=mediatek",
        "https://www.chipsets.org/search?q=5g",
        "https://www.chipsets.org/"
    ]

    # Use a more realistic user agent with rotation
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36'
    ]

    headers = {
        'User-Agent': random.choice(user_agents),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }

    # Expanded list of cellular-related keywords
    cellular_keywords = [
        # General cellular terms
        'cellular', 'modem', 'baseband', 'radio', 'wireless', 'mobile', 'telecommunications',
        # Cellular standards
        'lte', '5g', '4g', '3g', '2g', 'gsm', 'cdma', 'umts', 'hsdpa', 'hspa', 'edge', 'gprs',
        # Chipset manufacturers known for cellular tech
        'qualcomm', 'mediatek', 'exynos', 'kirin', 'snapdragon', 'intel xmm', 'broadcom',
        # Cellular components
        'transceiver', 'rf', 'radio frequency', 'antenna', 'sim', 'esim', 'imei',
        # Protocols
        'rrc', 'nas', 'sms', 'ussd', 'ss7', 'diameter',
        # Cellular-specific attack surface
        'basestation', 'cell tower', 'femtocell', 'small cell'
    ]

    # Lists to store all found CVEs and tracked URLs
    cellular_cves = {}  # Use dict for faster duplicate checking
    processed_urls = set()
    urls_to_process = []

    # Timestamp for backup files
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = f"cellular_cves_backup_{timestamp}.csv"

    def is_cellular_related(text):
        """Check if text contains any cellular-related keywords"""
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in cellular_keywords)

    def extract_cves(text, source_url):
        """Extract CVEs from text and add to our list if they're new"""
        # Look for CVE IDs
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
        cve_ids = cve_pattern.findall(text)

        new_cves_found = 0

        for cve_id in cve_ids:
            standardized_id = cve_id.upper()  # Standardize format

            # Skip if we've already recorded this CVE
            if standardized_id in cellular_cves:
                continue

            # Clean up text
            description = re.sub(r'\s+', ' ', text).strip()

            # Limit length but keep relevant context
            if len(description) > 1000:
                # Try to find the CVE ID position and keep text around it
                cve_pos = description.upper().find(standardized_id)
                if cve_pos != -1:
                    start = max(0, cve_pos - 300)
                    end = min(len(description), cve_pos + len(standardized_id) + 700)
                    description = description[start:end]
                else:
                    description = description[:1000]

            # Check if the description is cellular-related
            is_cellular = is_cellular_related(description)

            # Add to our dict of findings
            cellular_cves[standardized_id] = {
                'cve_id': standardized_id,
                'description': description,
                'source': source_url,
                'is_cellular_related': is_cellular
            }
            new_cves_found += 1

            if is_cellular:
                print(f"Found cellular-related CVE: {standardized_id}")
            else:
                print(f"Found CVE: {standardized_id}")

        return new_cves_found

    def extract_links(soup, current_url):
        """Extract relevant links from the page with intelligent filtering"""
        vulnerability_links = []
        pagination_links = []
        other_links = []

        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            link_text = a_tag.get_text().strip().lower()

            # Skip non-http links and anchors
            if href.startswith('javascript:') or href == '#' or href.startswith('mailto:'):
                continue

            # Create absolute URL
            full_url = urljoin(current_url, href)

            # Only include links to the same domain
            if base_url not in full_url or full_url in processed_urls or full_url in urls_to_process:
                continue

            # Categorize links by relevance
            url_lower = full_url.lower()

            # High priority: Vulnerability/CVE pages
            if ('vulnerab' in url_lower or 'cve-' in url_lower or 'security' in url_lower):
                vulnerability_links.append(full_url)
            # Medium priority: Pagination links
            elif ('page' in link_text or re.search(r'/page/\d+', url_lower) or
                  re.search(r'[?&]p(age)?=\d+', url_lower) or
                  any(char in link_text for char in ['›', '»', 'next'])):
                pagination_links.append(full_url)
            # Low priority: Cellular-related content pages
            elif any(keyword in url_lower for keyword in cellular_keywords):
                vulnerability_links.append(full_url)
            # Lowest priority: Other site pages
            else:
                other_links.append(full_url)

        # Return prioritized links
        return vulnerability_links, pagination_links, other_links

    def save_backup():
        """Save current progress to backup file"""
        cve_list = list(cellular_cves.values())
        with open(backup_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['cve_id', 'description', 'source', 'is_cellular_related']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for cve in cve_list:
                writer.writerow(cve)
        print(f"Backup saved to {backup_file} with {len(cve_list)} CVEs")

    # Start by adding all starting points to our processing queue
    for url in starting_points:
        if url not in urls_to_process and url not in processed_urls:
            urls_to_process.append(url)

    # Process pages in a prioritized manner
    page_count = 0
    last_backup_count = 0
    backup_frequency = 50  # Create backup every 50 pages

    while urls_to_process and page_count < max_pages:
        current_url = urls_to_process.pop(0)
        processed_urls.add(current_url)
        page_count += 1

        # Rotate user agent for each request
        headers['User-Agent'] = random.choice(user_agents)

        try:
            print(f"[{page_count}/{max_pages}] Processing: {current_url}")

            # Random delay between requests (1-3 seconds)
            sleep(1 + random.random() * 2)

            response = requests.get(current_url, headers=headers, timeout=30)

            # Skip non-successful responses
            if response.status_code != 200:
                print(f"  Skipping: Status code {response.status_code}")
                continue

            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract all text from the page
            page_text = soup.get_text()

            # Process page for CVEs
            new_cves = extract_cves(page_text, current_url)

            # More specific processing for structured content

            # 1. Process tables
            tables = soup.find_all('table')
            for table in tables:
                rows = table.find_all('tr')
                for row in rows:
                    extract_cves(row.get_text(), current_url)

            # 2. Process lists
            for ul in soup.find_all(['ul', 'ol']):
                for li in ul.find_all('li'):
                    extract_cves(li.get_text(), current_url)

            # 3. Process divs with security-related attributes
            for div in soup.find_all('div'):
                div_attrs = str(div.get('class', '')) + str(div.get('id', ''))
                if any(term in div_attrs.lower() for term in ['vuln', 'cve', 'security', 'advisory']):
                    extract_cves(div.get_text(), current_url)

            # Extract links for next pages to process
            vuln_links, page_links, other_links = extract_links(soup, current_url)

            # Add prioritized links to the processing queue
            # Vulnerability links at the beginning
            urls_to_process = vuln_links + urls_to_process

            # Pagination links come next
            urls_to_process.extend(page_links)

            # Other links last, limited to prevent excessive breadth
            if len(urls_to_process) < 100:  # Only add more if our queue is manageable
                urls_to_process.extend(other_links[:10])  # Limit to 10 other links

            # Create periodic backups
            if page_count % backup_frequency == 0 or page_count - last_backup_count >= backup_frequency:
                save_backup()
                last_backup_count = page_count

        except Exception as e:
            print(f"Error processing {current_url}: {e}")

    # Convert dict back to list for final processing
    final_cves = list(cellular_cves.values())

    # Sort results: cellular-related CVEs first, then by CVE ID
    final_cves.sort(key=lambda x: (not x['is_cellular_related'], x['cve_id']))

    # Export results to CSV
    if final_cves:
        with open('cellular_cves_from_chipsets_org_final.csv', 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['cve_id', 'description', 'source', 'is_cellular_related']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for cve in final_cves:
                writer.writerow(cve)

        # Count confirmed cellular CVEs
        confirmed_cellular = sum(1 for cve in final_cves if cve['is_cellular_related'])

        print(f"\nScraping complete!")
        print(f"- Pages processed: {page_count}")
        print(f"- Total CVEs found: {len(final_cves)}")
        print(f"- Cellular-related CVEs: {confirmed_cellular}")
        print(f"Results saved to cellular_cves_from_chipsets_org_final.csv")

        # Show sample of cellular CVEs
        if confirmed_cellular > 0:
            print("\nSample of cellular-related CVEs found:")
            sample_count = 0
            for cve in final_cves:
                if cve['is_cellular_related'] and sample_count < 5:
                    print(f"- {cve['cve_id']} (Source: {cve['source']})")
                    sample_count += 1
    else:
        print("No CVEs found")

    return final_cves


if __name__ == "__main__":
    print("Starting large-scale scraping of Chipsets.org for cellular-related CVEs...")
    # Increase max_pages to handle websites with many pages (default is 500)
    results = scrape_chipsets_org_vulnerabilities(max_pages=500)
    print("Scraping completed.")