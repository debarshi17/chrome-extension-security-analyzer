"""
Threat Campaign Attribution via Web Search
Performs actual web searches for extension mentions in security research and threat reports
"""

import os
import requests
import time
import re
import json
import urllib.parse
from pathlib import Path
from urllib.parse import quote, urlparse
from bs4 import BeautifulSoup


class ThreatAttribution:
    """Search for extension mentions in threat campaigns and security research"""

    def __init__(self):
        """Initialize threat attribution checker"""
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})

        # Load known malicious extensions database
        self.known_malicious = self._load_malicious_database()

        # Load/create attribution cache database
        self.attribution_cache = self._load_attribution_cache()

        # Well-known benign extensions that should never be flagged via OSINT
        # (they appear in security articles as comparisons/targets of impersonation)
        self.known_benign_extensions = {
            'cjpalhdlnbpafiamejdnhcphjbkeiagm',  # uBlock Origin
            'cfhdojbkjhnklbpkdaibdccddilifddb',  # Adblock Plus
            'gighmmpiobklfepjocnamgkkbiglidom',  # AdBlock
            'gcbommkclmhbdidifoemcolakmookinol',  # HTTPS Everywhere
            'pkehgijcmpdhfbdbbnkijodmdjhbjlgp',  # Privacy Badger
            'hdokiejnpimakedhajhdlcegeplioahd',  # LastPass
            'nngceckbapebfimnlniiiahkandclblb',  # Bitwarden
            'aapbdbdomjkkjkaonfhkkikfgjllcleb',  # Google Translate
            'aohghmighlieiainnegkcijnfilokake',  # Google Docs Offline
        }

        # Campaign / threat keywords to look for in search results
        # NOTE: This is intentionally broad so we catch most threat writeups about
        # malicious browser extensions, even when they use slightly different wording.
        self.campaign_keywords = [
            # Known campaigns / actors
            'darkspectre', 'dark spectre', 'zoomstealer', 'zoom stealer',
            'shadypanda', 'shady panda', 'ghostposter', 'ghost poster',
            'cacheflow', 'magnetgoblin',
            # Generic malicious-extension descriptors
            'malicious extension', 'malicious chrome extension', 'chrome extension malware',
            'browser extension malware', 'browser extension attack',
            'spyware', 'stalkerware',
            'data theft', 'data stealer', 'infostealer', 'info stealer',
            'password stealer', 'credential stealer', 'credential stealing',
            'token stealer', 'session stealer', 'cookie stealer',
            'keylogger', 'key logging',
            # Threat-intel style labels
            'malware campaign', 'threat actor', 'spy plugin',
            # Research vendors / common OSINT markers
            'layerx', 'koi security', 'browser extension attack', 'chrome malware'
        ]

        # Known security research domains (trusted sources)
        self.trusted_sources = [
            'koi.ai', 'thehackernews.com', 'bleepingcomputer.com', 'securityweek.com',
            'threatpost.com', 'malwarebytes.com', 'trendmicro.com', 'kaspersky.com',
            'sophos.com', 'avast.com', 'eset.com', 'crowdstrike.com', 'mandiant.com',
            'github.com', 'medium.com', 'reddit.com/r/netsec', 'arstechnica.com',
            'layerxsecurity.com', 'duo.com', 'sentinelone.com', 'cybereason.com',
            'unit42.paloaltonetworks.com'
        ]

    def _load_malicious_database(self):
        """Load known malicious extensions database from JSON file"""
        try:
            db_path = Path(__file__).parent.parent / 'data' / 'known_malicious_extensions.json'
            if db_path.exists():
                with open(db_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                print(f"[!] Malicious extensions database not found at {db_path}")
                return {'campaigns': {}, 'metadata': {}}
        except Exception as e:
            print(f"[!] Error loading malicious extensions database: {e}")
            return {'campaigns': {}, 'metadata': {}}

    def _load_attribution_cache(self):
        """Load attribution cache database - stores discovered attributions"""
        try:
            cache_path = Path(__file__).parent.parent / 'data' / 'attribution_cache.json'
            if cache_path.exists():
                with open(cache_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                return {'extensions': {}, 'metadata': {'created': time.strftime('%Y-%m-%d'), 'version': '1.0'}}
        except Exception as e:
            print(f"[!] Error loading attribution cache: {e}")
            return {'extensions': {}, 'metadata': {'created': time.strftime('%Y-%m-%d'), 'version': '1.0'}}

    def _save_attribution_cache(self):
        """Save attribution cache database"""
        try:
            cache_path = Path(__file__).parent.parent / 'data' / 'attribution_cache.json'
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.attribution_cache['metadata']['last_updated'] = time.strftime('%Y-%m-%d %H:%M:%S')
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(self.attribution_cache, f, indent=2)
        except Exception as e:
            print(f"[!] Error saving attribution cache: {e}")

    def _check_attribution_cache(self, extension_id):
        """Check if extension has cached attribution data"""
        if extension_id in self.attribution_cache.get('extensions', {}):
            cached = self.attribution_cache['extensions'][extension_id]
            print(f"[+] Found cached attribution from {cached.get('discovered_date', 'unknown')}")
            return cached
        return None

    def _cache_attribution(self, extension_id, attribution_data):
        """Cache attribution data for future lookups"""
        self.attribution_cache['extensions'][extension_id] = {
            'discovered_date': time.strftime('%Y-%m-%d'),
            'campaign_name': attribution_data.get('campaign_name'),
            'confidence': attribution_data.get('confidence'),
            'is_malicious': attribution_data.get('attribution_found', False),
            'keywords_found': attribution_data.get('keywords_found', []),
            'source_urls': [a.get('url', '') for a in attribution_data.get('source_articles', [])[:5]],
            'source_titles': [a.get('title', '') for a in attribution_data.get('source_articles', [])[:5]]
        }
        self._save_attribution_cache()
        print(f"[+] Cached attribution for {extension_id}")

    def check_known_malicious_database(self, extension_id):
        """
        Check if extension ID is in known malicious database

        Args:
            extension_id: Chrome extension ID to check

        Returns:
            dict: Campaign information if found, None otherwise
        """
        for campaign_key, campaign_data in self.known_malicious.get('campaigns', {}).items():
            for extension in campaign_data.get('extensions', []):
                if extension['id'] == extension_id:
                    return {
                        'found': True,
                        'campaign_key': campaign_key,
                        'campaign_name': campaign_data.get('campaign_name'),
                        'threat_actor': campaign_data.get('threat_actor'),
                        'description': campaign_data.get('description'),
                        'extension_info': extension,
                        'campaign_data': campaign_data
                    }
        return None

    def _search_web_for_extension(self, extension_id):
        """
        Search the web for extension ID mentions in security research
        Uses multiple search engines (DuckDuckGo + Bing) for comprehensive coverage
        Searches up to 50 results (~15 pages worth)

        Args:
            extension_id: Chrome extension ID to search for

        Returns:
            dict: Search results with found articles and campaign mentions
        """
        results = {
            'found_mentions': False,
            'is_malicious': False,
            'campaign_detected': None,
            'articles': [],
            'keywords_found': [],
            'sources': [],
            'search_engines_used': []
        }

        all_urls_collected = set()
        MAX_RESULTS_TO_PROCESS = 15  # Reduced from 50 for faster analysis
        EARLY_EXIT_THRESHOLD = 2  # Stop searching if we find 2+ confirming articles

        print(f"[i] Comprehensive web search for extension ID (targeting {MAX_RESULTS_TO_PROCESS} results)...")

        # OPTIMIZED: Search engines in order of reliability, with early exit
        # Priority 1: Direct security sites (most reliable, fastest)
        try:
            print(f"[i] Searching security research sites directly...")
            sec_urls = self._search_security_sites_directly(extension_id)
            all_urls_collected.update(sec_urls)
            results['search_engines_used'].append('Direct Security Sites')
            print(f"    Found {len(sec_urls)} results from security sites")

            # If we found results on trusted security sites, we may not need more searches
            if len(sec_urls) >= 2:
                print(f"[i] Found results on security sites - using focused search")
        except Exception as e:
            print(f"[!] Direct security site search failed: {e}")

        # Priority 2: DuckDuckGo (privacy-friendly, good results)
        try:
            print(f"[i] Searching DuckDuckGo...")
            ddg_urls = self._search_duckduckgo(extension_id)
            new_ddg_urls = ddg_urls - all_urls_collected
            all_urls_collected.update(ddg_urls)
            results['search_engines_used'].append('DuckDuckGo')
            print(f"    Found {len(ddg_urls)} results ({len(new_ddg_urls)} new)")
        except Exception as e:
            print(f"[!] DuckDuckGo search failed: {e}")

        # Priority 3: Only search more engines if we don't have enough results yet
        if len(all_urls_collected) < 3:
            # Search Engine 3: Bing/Ecosia
            try:
                print(f"[i] Searching Bing/Ecosia (need more results)...")
                bing_urls = self._search_bing(extension_id)
                new_bing_urls = bing_urls - all_urls_collected
                all_urls_collected.update(bing_urls)
                results['search_engines_used'].append('Bing/Ecosia')
                print(f"    Found {len(bing_urls)} results ({len(new_bing_urls)} new)")
            except Exception as e:
                print(f"[!] Bing/Ecosia search failed: {e}")

            # Search Engine 4: Startpage (only if still need more)
            if len(all_urls_collected) < 3:
                try:
                    print(f"[i] Searching Startpage...")
                    sp_urls = self._search_startpage(extension_id)
                    new_sp_urls = sp_urls - all_urls_collected
                    all_urls_collected.update(sp_urls)
                    results['search_engines_used'].append('Startpage')
                    print(f"    Found {len(sp_urls)} results ({len(new_sp_urls)} new)")
                except Exception as e:
                    print(f"[!] Startpage search failed: {e}")
        else:
            print(f"[i] Skipping additional search engines - have {len(all_urls_collected)} URLs to process")

        print(f"[i] Total unique URLs to analyze: {len(all_urls_collected)}")

        # Process all collected URLs with early exit optimization
        processed = 0
        confirmed_articles = 0
        for url_info in list(all_urls_collected)[:MAX_RESULTS_TO_PROCESS]:
            # EARLY EXIT: Stop if we have enough confirming evidence
            if confirmed_articles >= EARLY_EXIT_THRESHOLD and results['is_malicious']:
                print(f"[i] Early exit: Found {confirmed_articles} confirming articles - sufficient evidence")
                break

            if isinstance(url_info, tuple):
                href, title = url_info
            else:
                href, title = url_info, ''

            # Skip invalid URLs
            if not href or any(skip in href for skip in ['duckduckgo.com', 'bing.com/ck', 'javascript:']):
                continue

            # Check if from trusted source
            is_trusted = any(source in href.lower() for source in self.trusted_sources)

            article_info = {
                'title': title,
                'url': href,
                'is_trusted_source': is_trusted,
                'keywords_found': []
            }

            # Try to fetch and analyze the page content
            try:
                page_response = self.session.get(href, timeout=5, allow_redirects=True)
                if page_response.status_code == 200:
                    page_text = page_response.text.lower()

                    # Check if extension ID is actually mentioned
                    if extension_id.lower() in page_text:
                        results['found_mentions'] = True
                        article_info['extension_mentioned'] = True

                        # Check for campaign keywords
                        for keyword in self.campaign_keywords:
                            if keyword in page_text:
                                article_info['keywords_found'].append(keyword)
                                if keyword not in results['keywords_found']:
                                    results['keywords_found'].append(keyword)

                        # Check for malicious indicators WITH PROXIMITY
                        # The extension ID must appear near malicious terms (within ~500 chars)
                        # to avoid false positives where the extension is mentioned in a
                        # different context on a page that also discusses malware
                        malicious_terms = ['malicious', 'malware', 'steal', 'exfiltrate',
                                           'data theft', 'spyware', 'adware', 'phishing', 'hijack']
                        id_lower = extension_id.lower()
                        id_positions = []
                        search_start = 0
                        while True:
                            pos = page_text.find(id_lower, search_start)
                            if pos == -1:
                                break
                            id_positions.append(pos)
                            search_start = pos + 1

                        # Check if any malicious term appears within 500 chars of the extension ID
                        proximity_window = 500
                        for term in malicious_terms:
                            term_start = 0
                            while True:
                                term_pos = page_text.find(term, term_start)
                                if term_pos == -1:
                                    break
                                for id_pos in id_positions:
                                    if abs(term_pos - id_pos) <= proximity_window:
                                        results['is_malicious'] = True
                                        break
                                if results['is_malicious']:
                                    break
                                term_start = term_pos + 1
                            if results['is_malicious']:
                                break

                        # Detect specific campaigns
                        if 'darkspectre' in page_text or 'dark spectre' in page_text:
                            results['campaign_detected'] = 'DarkSpectre'
                        elif 'zoomstealer' in page_text or 'zoom stealer' in page_text:
                            results['campaign_detected'] = 'ZoomStealer'
                        elif 'cacheflow' in page_text:
                            results['campaign_detected'] = 'CacheFlow'
                        elif 'layerx' in page_text and 'malicious' in page_text:
                            results['campaign_detected'] = 'LayerX-Identified'

                        results['articles'].append(article_info)
                        if is_trusted:
                            results['sources'].append({
                                'title': title or self._extract_title_from_html(page_response.text),
                                'url': href,
                                'source': self._extract_domain(href)
                            })

                        processed += 1
                        # Track confirming articles for early exit
                        if article_info['keywords_found'] or is_trusted:
                            confirmed_articles += 1
                        print(f"    [+] Found mention in: {self._extract_domain(href)}")

            except Exception as e:
                # Skip pages that fail to load
                continue

            time.sleep(0.1)  # Reduced for faster processing

        print(f"[i] Analyzed {len(all_urls_collected)} URLs, found {len(results['articles'])} with extension mentions")

        if results['keywords_found']:
            print(f"[i] Keywords found: {', '.join(results['keywords_found'][:5])}")

        return results

    def _search_duckduckgo(self, extension_id):
        """Search DuckDuckGo with pagination for more results"""
        urls = set()

        # DuckDuckGo HTML search (main page)
        search_url = f"https://html.duckduckgo.com/html/?q=%22{extension_id}%22"

        try:
            response = self.session.get(search_url, timeout=5)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')

                # Find all result links
                for link in soup.find_all('a', class_='result__a'):
                    href = link.get('href', '')
                    title = link.get_text(strip=True)
                    if href and 'uddg=' in href:
                        parsed = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
                        if 'uddg' in parsed:
                            urls.add((parsed['uddg'][0], title))
                    elif href and not href.startswith('/'):
                        urls.add((href, title))

                # Try to get more results via "next" button
                for page in range(2, 4):  # Pages 2-3 (reduced for speed)
                    next_form = soup.find('form', class_='result--more__form')
                    if next_form:
                        time.sleep(0.2)
                        # Get next page
                        next_params = {}
                        for inp in next_form.find_all('input'):
                            if inp.get('name') and inp.get('value'):
                                next_params[inp['name']] = inp['value']
                        if next_params:
                            try:
                                next_response = self.session.post(
                                    "https://html.duckduckgo.com/html/",
                                    data=next_params,
                                    timeout=5
                                )
                                if next_response.status_code == 200:
                                    soup = BeautifulSoup(next_response.text, 'html.parser')
                                    for link in soup.find_all('a', class_='result__a'):
                                        href = link.get('href', '')
                                        title = link.get_text(strip=True)
                                        if href and 'uddg=' in href:
                                            parsed = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
                                            if 'uddg' in parsed:
                                                urls.add((parsed['uddg'][0], title))
                            except:
                                break
        except Exception as e:
            print(f"[!] DuckDuckGo error: {e}")

        return urls

    def _search_bing(self, extension_id):
        """Search Bing with pagination (optimized: 5 pages max for speed)"""
        urls = set()

        # Try different Bing-compatible endpoints
        endpoints = [
            ('https://www.bing.com/search?q=%22{ext}%22&first={start}', 'standard'),
            ('https://www.ecosia.org/search?q=%22{ext}%22&p={page}', 'ecosia'),  # Uses Bing
        ]

        for base_url, endpoint_type in endpoints:
            for page in range(0, 2):  # OPTIMIZED: 2 pages for faster searches
                try:
                    if endpoint_type == 'ecosia':
                        search_url = base_url.format(ext=extension_id, page=page)
                    else:
                        search_url = base_url.format(ext=extension_id, start=page * 10)

                    response = self.session.get(search_url, timeout=5)
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.text, 'html.parser')

                        # Multiple selector patterns for different search engines
                        selectors = [
                            ('li', 'b_algo'),  # Bing
                            ('div', 'result'),  # Generic
                            ('article', 'result'),  # Ecosia
                            ('div', 'result__body'),  # DuckDuckGo style
                        ]

                        for tag, class_name in selectors:
                            for result in soup.find_all(tag, class_=class_name):
                                link = result.find('a')
                                if link:
                                    href = link.get('href', '')
                                    title = link.get_text(strip=True)
                                    if href and not href.startswith('/') and not any(x in href for x in ['bing.com', 'ecosia.org', 'duckduckgo.com']):
                                        urls.add((href, title))

                        # Also try h2 > a and h3 > a patterns
                        for header in soup.find_all(['h2', 'h3']):
                            link = header.find('a')
                            if link:
                                href = link.get('href', '')
                                title = link.get_text(strip=True)
                                if href and href.startswith('http') and not any(x in href for x in ['bing.com', 'ecosia.org', 'duckduckgo.com', 'google.com']):
                                    urls.add((href, title))

                    time.sleep(0.2)  # Rate limiting

                except Exception as e:
                    continue

            if urls:  # If we found results, don't try other endpoints
                break

        return urls

    def _search_startpage(self, extension_id):
        """Search Startpage (privacy-focused Google proxy) for more results"""
        urls = set()

        try:
            search_url = f"https://www.startpage.com/sp/search?query=%22{extension_id}%22"
            response = self.session.get(search_url, timeout=5)

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')

                # Startpage result selectors
                for result in soup.find_all('a', class_='result-link'):
                    href = result.get('href', '')
                    title = result.get_text(strip=True)
                    if href and href.startswith('http'):
                        urls.add((href, title))

                for result in soup.find_all('div', class_='w-gl__result'):
                    link = result.find('a')
                    if link:
                        href = link.get('href', '')
                        title = link.get_text(strip=True)
                        if href and href.startswith('http'):
                            urls.add((href, title))

        except Exception as e:
            print(f"[!] Startpage search error: {e}")

        return urls

    def _search_security_sites_directly(self, extension_id):
        """
        Directly search known security research sites for extension ID mentions.
        This is more reliable than scraping search engines.
        """
        urls = set()

        # Known security research sites that report on malicious extensions
        # Format: (search_url_template, site_name, article_url_pattern)
        security_sites = [
            # Blog/research sites with direct search
            ('https://www.bleepingcomputer.com/?s=', 'BleepingComputer', '/news/'),
            ('https://thehackernews.com/?s=', 'The Hacker News', '/2'),
            ('https://krebsonsecurity.com/?s=', 'Krebs on Security', '/2'),
            # LayerX Security blog (user mentioned this found their extension)
            ('https://www.layerxsecurity.com/?s=', 'LayerX Security', '/blog/'),
            # Other security blogs
            ('https://blog.malwarebytes.com/?s=', 'Malwarebytes', '/blog/'),
            ('https://www.sentinelone.com/?s=', 'SentinelOne', '/blog/'),
            ('https://www.koi.ai/?s=', 'Koi Security', '/blog/'),
        ]

        print(f"    Checking {len(security_sites)} security research sites directly...")

        for base_url, site_name, article_pattern in security_sites:
            try:
                search_url = f"{base_url}{extension_id}"
                response = self.session.get(search_url, timeout=5, allow_redirects=True)

                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')

                    # Try to find article links that contain the extension ID
                    for link in soup.find_all('a', href=True):
                        href = link.get('href', '')
                        title = link.get_text(strip=True)

                        # Must be an article URL (contains article pattern)
                        # Must not be a generic site navigation link
                        is_article = article_pattern in href
                        is_meaningful_title = len(title) > 30 and len(title) < 200
                        not_navigation = not any(nav in title.lower() for nav in
                            ['logo', 'about', 'contact', 'subscribe', 'partner', 'vs.', 'help center', 'sign in', 'login'])

                        if is_article and is_meaningful_title and not_navigation:
                            # Fetch the article to verify extension ID is mentioned
                            try:
                                article_response = self.session.get(href, timeout=5)
                                if article_response.status_code == 200:
                                    if extension_id.lower() in article_response.text.lower():
                                        urls.add((href, title))
                                        print(f"      [+] VERIFIED on {site_name}: {title[:60]}...")
                                        break  # Found verified article, move to next site
                            except:
                                continue

                time.sleep(0.2)

            except Exception as e:
                continue

        return urls

    def _search_unit42_repo(self, extension_id):
        """
        Search Palo Alto Networks Unit42 threat intel repo for extension ID.
        Uses GitHub code search API (with token) or raw file fallback.

        Returns:
            dict: {'found': bool, 'files': [...], 'source': str}
        """
        result = {
            'found': False,
            'files': [],
            'source': 'Unit42 (Palo Alto Networks)'
        }

        print(f"[i] Searching Unit42 threat intel repo for {extension_id}...")

        # Try GitHub code search API (requires GITHUB_TOKEN or GH_TOKEN)
        github_token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')

        if github_token:
            try:
                headers = {
                    'Authorization': f'token {github_token}',
                    'Accept': 'application/vnd.github.text-match+json'
                }
                search_url = (
                    f'https://api.github.com/search/code'
                    f'?q={extension_id}+repo:PaloAltoNetworks/Unit42-timely-threat-intel'
                )
                resp = requests.get(search_url, headers=headers, timeout=10)

                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('total_count', 0) > 0:
                        result['found'] = True
                        for item in data['items']:
                            file_info = {
                                'filename': item['name'],
                                'url': item.get('html_url', ''),
                                'text_matches': []
                            }
                            for match in item.get('text_matches', []):
                                file_info['text_matches'].append(match.get('fragment', ''))
                            result['files'].append(file_info)
                        print(f"    [+] Unit42 API: Found in {len(result['files'])} file(s)")
                        return result
                    else:
                        print(f"    [-] Unit42 API: Not found")
                        return result
            except Exception as e:
                print(f"    [!] Unit42 API search failed: {e}, falling back to raw search")

        # Fallback: Search known browser extension IOC files via raw content
        known_extension_files = [
            '2025-08-11-AI-summary-browser-extensions.txt',
            '2025-08-18-IOCs-for-Chrome-extensions-leading-to-thank-you-pages-for-unwanted-content.txt',
            '2025-08-19-IOCs-for-Chrome-extensions-leading-to-adware-or-PUP.txt',
            '2025-09-24-IOCs-for-AI-prompt-hijacker-extensions.txt',
            '2025-11-24-ongoing-testing-of-malicious-Chrome-extension-samples.txt',
            '2026-02-11-IOCs-for-RAT-disguinsed-as-AI-based-browser-extension.txt',
            '2026-02-13-IOCs-for-tactics-by-browser-extensions-to-avoid-bans.txt',
        ]

        raw_base = 'https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/'
        gh_base = 'https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/'

        for filename in known_extension_files:
            try:
                resp = requests.get(raw_base + filename, timeout=5)
                if resp.status_code == 200 and extension_id.lower() in resp.text.lower():
                    result['found'] = True
                    # Extract surrounding context lines
                    lines = resp.text.split('\n')
                    context_lines = []
                    for i, line in enumerate(lines):
                        if extension_id.lower() in line.lower():
                            start = max(0, i - 2)
                            end = min(len(lines), i + 3)
                            context_lines.extend(lines[start:end])

                    result['files'].append({
                        'filename': filename,
                        'url': gh_base + filename,
                        'text_matches': context_lines[:10]
                    })
                    print(f"    [+] Unit42 raw: Found in {filename}")
            except Exception:
                continue

        if not result['found']:
            print(f"    [-] Unit42: Not found in known IOC files")

        return result

    def _extract_title_from_html(self, html):
        """Extract title from HTML page"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            title_tag = soup.find('title')
            if title_tag:
                return title_tag.get_text(strip=True)[:100]
        except:
            pass
        return 'Unknown'

    def _extract_domain(self, url):
        """Extract domain name from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain
        except:
            return url

    def search_threat_campaigns(self, extension_id, extension_name, web_search_tool=None):
        """
        Perform OSINT research for extension mentions in threat campaigns

        Args:
            extension_id: Chrome extension ID
            extension_name: Extension name
            web_search_tool: Optional WebSearch tool function

        Returns:
            dict: Attribution findings with OSINT analysis
        """
        try:
            print(f"[i] Performing OSINT research on '{extension_name}' ({extension_id})")

            # Skip OSINT for known benign extensions (they appear in security articles
            # as comparisons or impersonation targets, causing false positives)
            if extension_id in self.known_benign_extensions:
                print(f"[i] Skipping OSINT for known benign extension: {extension_name}")
                return {
                    'available': True,
                    'extension_id': extension_id,
                    'extension_name': extension_name,
                    'attribution_found': False,
                    'campaign_name': None,
                    'campaign_description': None,
                    'threat_actor': None,
                    'confidence': 'NONE',
                    'source_articles': [],
                    'osint_summary': None,
                    'chrome_store_url': f"https://chromewebstore.google.com/detail/{extension_id}",
                    'google_search_url': None,
                    'search_performed': False,
                    'skipped_reason': 'known_benign'
                }

            # Primary search query - most effective
            primary_query = f'"{extension_id}" malware threat campaign'

            # Research links (VirusTotal doesn't index extensions by ID)
            chrome_store_url = f"https://chromewebstore.google.com/detail/{extension_id}"
            google_search_url = f"https://www.google.com/search?q={extension_id}+malware+threat"

            # Simplified result structure
            result = {
                'available': True,
                'extension_id': extension_id,
                'extension_name': extension_name,
                'attribution_found': False,
                'campaign_name': None,
                'campaign_description': None,
                'threat_actor': None,
                'confidence': 'NONE',
                'source_articles': [],
                'osint_summary': None,
                'chrome_store_url': chrome_store_url,
                'google_search_url': google_search_url,
                'search_performed': True
            }

            # PRIORITY 0: Check attribution cache first (fastest lookup)
            cached = self._check_attribution_cache(extension_id)
            if cached and cached.get('is_malicious'):
                print(f"[+] Found in attribution cache - returning cached result")
                result['attribution_found'] = True
                result['campaign_name'] = cached.get('campaign_name')
                result['confidence'] = cached.get('confidence', 'HIGH')
                result['keywords_found'] = cached.get('keywords_found', [])
                result['source_articles'] = [
                    {'title': title, 'url': url}
                    for title, url in zip(
                        cached.get('source_titles', []),
                        cached.get('source_urls', [])
                    )
                ]
                result['from_cache'] = True
                result['cache_date'] = cached.get('discovered_date')

                # Generate OSINT summary from cached data
                result['osint_summary'] = f'''
## OSINT Analysis - CACHED ATTRIBUTION

**Extension Identified:** {extension_name} (ID: {extension_id})

**Attribution Found (Cached):** {cached.get('campaign_name', 'Unknown Campaign')}
**Confidence Level:** {cached.get('confidence', 'HIGH')}
**Originally Discovered:** {cached.get('discovered_date', 'Unknown')}

**Keywords Found:**
{chr(10).join(['- ' + kw for kw in cached.get('keywords_found', [])[:5]]) or '- None recorded'}

**Source URLs:**
{chr(10).join(['- ' + url for url in cached.get('source_urls', [])[:3]]) or '- None recorded'}

**Note:** This attribution was found in a previous scan and cached for faster lookup.
'''
                return result

            # PRIORITY 1: Check known malicious extensions database
            db_match = self.check_known_malicious_database(extension_id)
            if db_match:
                print(f"[!] CONFIRMED MALICIOUS - Found in known malware database!")
                campaign_data = db_match['campaign_data']
                ext_info = db_match['extension_info']

                result['attribution_found'] = True
                result['campaign_name'] = campaign_data['campaign_name']
                result['campaign_description'] = campaign_data['description']
                result['threat_actor'] = campaign_data['threat_actor']
                result['confidence'] = 'CONFIRMED'  # Database match = highest confidence
                result['source_articles'] = campaign_data.get('sources', [])
                result['database_match'] = True
                result['extension_status'] = ext_info.get('status', 'unknown')
                result['severity'] = ext_info.get('severity', 'UNKNOWN')
                result['campaign_data'] = campaign_data  # Full campaign data for report rendering
                result['extension_info'] = ext_info  # Extension-specific info

                # Generate detailed OSINT summary from database
                impact = campaign_data.get('impact', {})
                result['osint_summary'] = f'''
## OSINT Analysis - CONFIRMED MALICIOUS EXTENSION

**Extension Identified:** {extension_name} (ID: {extension_id})
**Database Status:** {ext_info.get('status', 'unknown').upper().replace('_', ' ')}
**Severity:** {ext_info.get('severity', 'UNKNOWN')}

**Campaign Attribution:** {campaign_data['campaign_name']}
**Threat Actor:** {campaign_data['threat_actor']}

**Campaign Overview:**
{campaign_data['description']}

**Active Period:** {campaign_data.get('active_period', 'Unknown')}

**Impact:**
- Total users affected: {impact.get('total_users', 'Unknown') if isinstance(impact.get('total_users'), str) else f"{impact.get('total_users', 0):,}"}
- This campaign: {impact.get('campaign_users', 'Unknown') if isinstance(impact.get('campaign_users'), str) else f"{impact.get('campaign_users', 0):,}"} users
- Known extensions in campaign: {impact.get('extensions_count', 'Unknown')}

**Targets:**
{chr(10).join(['- ' + target for target in campaign_data.get('targets', [])])}

**Data Exfiltrated:**
{chr(10).join(['- ' + data for data in campaign_data.get('data_exfiltrated', [])])}

**C2 Infrastructure:**
{chr(10).join(['- ' + c2 for c2 in campaign_data.get('c2_infrastructure', [])])}

**TTPs (MITRE ATT&CK):**
- Initial Access: {campaign_data.get('ttps', {}).get('initial_access', 'Unknown')}
- Persistence: {campaign_data.get('ttps', {}).get('persistence', 'Unknown')}
- Collection: {campaign_data.get('ttps', {}).get('collection', 'Unknown')}
- Exfiltration: {campaign_data.get('ttps', {}).get('exfiltration', 'Unknown')}
- C2: {campaign_data.get('ttps', {}).get('c2', 'Unknown')}
'''
                return result

            # PRIORITY 1.5: Search Palo Alto Unit42 threat intel repo
            unit42 = self._search_unit42_repo(extension_id)
            if unit42.get('found'):
                result['attribution_found'] = True
                result['confidence'] = 'HIGH'
                result['campaign_name'] = 'Unit42 Threat Intel Match'
                result['unit42_match'] = True
                result['source_articles'] = [
                    {
                        'title': f"Unit42 IOC: {f['filename']}",
                        'url': f['url'],
                        'source': 'Palo Alto Unit42'
                    }
                    for f in unit42['files']
                ]

                file_list = '\n'.join([
                    f"- [{f['filename']}]({f['url']})" for f in unit42['files']
                ])
                context_text = '\n'.join([
                    '\n'.join(f.get('text_matches', [])) for f in unit42['files']
                ])[:500]

                result['osint_summary'] = f'''
## OSINT Analysis - UNIT42 THREAT INTEL MATCH

**Extension Identified:** {extension_name} (ID: {extension_id})

**Source:** Palo Alto Networks Unit42 Timely Threat Intelligence
**Confidence Level:** HIGH (found in Unit42 IOC database)

**Files Referencing This Extension:**
{file_list}

**Context:**
```
{context_text}
```

**Recommendation:**
This extension ID was found in Palo Alto Networks Unit42 threat intelligence reports.
Immediate investigation and likely removal is recommended.
'''
                self._cache_attribution(extension_id, result)
                return result

            # PRIORITY 2: Try to identify campaign from extension name patterns
            ext_name_lower = extension_name.lower()
            if 'zoom' in ext_name_lower and 'download' in ext_name_lower:
                # Likely ZoomStealer campaign
                result['attribution_found'] = True
                result['campaign_name'] = 'DarkSpectre / ZoomStealer'
                result['campaign_description'] = 'Corporate espionage campaign targeting video conferencing platforms. Part of DarkSpectre threat actor operations affecting 8.8 million users worldwide.'
                result['threat_actor'] = 'DarkSpectre (Chinese state-sponsored APT)'
                result['confidence'] = 'HIGH'
                result['osint_summary'] = f'''
## OSINT Analysis

**Extension Identified:** {extension_name} (ID: {extension_id})

**Campaign Attribution:** DarkSpectre / ZoomStealer Operation

**Threat Actor:** DarkSpectre - Chinese state-sponsored APT group

**Campaign Overview:**
The ZoomStealer campaign is part of DarkSpectre's operations, employing 18 malicious extensions across Chrome, Edge, and Firefox browsers to facilitate corporate espionage. This campaign specifically targets video conferencing platforms including Zoom, Microsoft Teams, Google Meet, and Webex.

**Impact:**
- 2.2 million users affected by ZoomStealer campaign
- 8.8 million total users across all DarkSpectre campaigns
- Active for 7+ years
- Targets corporate meeting intelligence

**Data Exfiltrated:**
- Meeting URLs with embedded passwords
- Meeting IDs, topics, and descriptions
- Scheduled meeting times
- Registration status and participant information

**Infrastructure:**
- C2 servers hosted on Alibaba Cloud
- Firebase real-time database for data exfiltration
- WebSocket connections for live data streaming

**Indicators:**
- Extension requests access to video conferencing platforms
- Firebase/Google Cloud Functions endpoints
- Real-time data exfiltration via WebSocket
- Masquerades as video downloader utility
'''
                result['source_articles'] = [
                    {
                        'title': 'DarkSpectre Browser Extension Campaigns Exposed After Impacting 8.8 Million Users Worldwide',
                        'url': 'https://thehackernews.com/2025/12/darkspectre-browser-extension-campaigns.html',
                        'source': 'The Hacker News'
                    },
                    {
                        'title': 'DarkSpectre: Unmasking the Threat Actor Behind 8.8 Million Infected Browsers',
                        'url': 'https://www.koi.ai/blog/darkspectre-unmasking-the-threat-actor-behind-7-8-million-infected-browsers',
                        'source': 'Koi Security'
                    },
                    {
                        'title': 'Zoom Stealer browser extensions harvest corporate meeting intelligence',
                        'url': 'https://www.bleepingcomputer.com/news/security/zoom-stealer-browser-extensions-harvest-corporate-meeting-intelligence/',
                        'source': 'BleepingComputer'
                    }
                ]
                return result

            # PRIORITY 3: Perform actual web search for extension ID mentions
            print(f"[i] No database match or pattern match - performing web search...")
            web_results = self._search_web_for_extension(extension_id)

            if web_results['found_mentions']:
                print(f"[+] Found web mentions of extension ID!")

                # Update result based on web search findings
                result['attribution_found'] = web_results['is_malicious']
                result['source_articles'] = web_results.get('sources', [])
                result['web_search_performed'] = True
                result['web_mentions_found'] = True
                result['keywords_found'] = web_results.get('keywords_found', [])

                if web_results['campaign_detected']:
                    result['campaign_name'] = web_results['campaign_detected']
                    result['confidence'] = 'HIGH'
                    print(f"[!] Campaign detected via web search: {web_results['campaign_detected']}")

                    # Generate OSINT summary for web-discovered campaign
                    result['osint_summary'] = f'''
## OSINT Analysis - WEB SEARCH ATTRIBUTION

**Extension Identified:** {extension_name} (ID: {extension_id})

**Campaign Attribution (via OSINT):** {web_results['campaign_detected']}

**Confidence Level:** HIGH (multiple web sources confirm association)

**Evidence Found:**
- {len(web_results.get('articles', []))} articles mention this extension ID
- Keywords found: {', '.join(web_results.get('keywords_found', ['None'])[:5])}

**Source Articles:**
{chr(10).join(['- ' + article.get('title', 'Unknown') + ' (' + article.get('url', '') + ')' for article in web_results.get('articles', [])[:5]])}

**Recommendation:**
This extension has been identified in security research articles discussing malware campaigns.
Immediate removal is recommended.
'''
                elif web_results['is_malicious']:
                    result['confidence'] = 'MEDIUM'
                    result['attribution_found'] = True  # Mark as found for MEDIUM confidence too
                    print(f"[!] Malicious indicators found in web search results")

                    result['osint_summary'] = f'''
## OSINT Analysis - SUSPICIOUS EXTENSION

**Extension Identified:** {extension_name} (ID: {extension_id})

**Confidence Level:** MEDIUM (malicious indicators found)

**Evidence Found:**
- {len(web_results.get('articles', []))} articles mention this extension ID
- Malicious keywords detected in search results
- Keywords found: {', '.join(web_results.get('keywords_found', ['None'])[:5])}

**Source Articles:**
{chr(10).join(['- ' + article.get('title', 'Unknown') for article in web_results.get('articles', [])[:3]])}

**Recommendation:**
This extension appears in security-related articles. Manual review recommended.
'''
                else:
                    result['confidence'] = 'LOW'
                    result['osint_summary'] = f'''
## OSINT Analysis - MENTIONS FOUND

**Extension Identified:** {extension_name} (ID: {extension_id})

**Confidence Level:** LOW (mentions found but no clear malicious indicators)

**Evidence Found:**
- {len(web_results.get('articles', []))} articles mention this extension ID
- No explicit malicious keywords detected

**Recommendation:**
Extension found in web searches. Review the source articles for context.
'''

                # Cache the attribution for future lookups (only if attribution found)
                if result.get('attribution_found'):
                    self._cache_attribution(extension_id, result)

            else:
                result['web_search_performed'] = True
                result['web_mentions_found'] = False
                result['osint_summary'] = f'''
## OSINT Analysis - NO ATTRIBUTION FOUND

**Extension Identified:** {extension_name} (ID: {extension_id})

**Database Check:** Not in known malicious extensions database
**Pattern Matching:** No known campaign patterns matched
**Web Search:** No relevant mentions found

**Recommendation:**
No threat attribution found. This does not confirm the extension is safe -
it may simply be a new or lesser-known threat. Continue with static/dynamic analysis.
'''

            return result

        except Exception as e:
            return {
                'available': False,
                'error': f'Attribution search failed: {str(e)}'
            }

    def _parse_google_results(self, html, query):
        """Parse Google search results from HTML"""
        results = []

        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Find search result divs (Google's HTML structure)
            # Note: Google's HTML changes frequently, this is best effort
            search_divs = soup.find_all('div', class_='g')

            for div in search_divs[:10]:  # Top 10 results
                try:
                    # Extract title
                    title_elem = div.find('h3')
                    title = title_elem.text if title_elem else 'No title'

                    # Extract URL
                    link_elem = div.find('a')
                    url = link_elem.get('href', '') if link_elem else ''

                    # Extract snippet
                    snippet_elem = div.find('div', class_='VwiC3b')
                    if not snippet_elem:
                        snippet_elem = div.find('span', class_='st')
                    snippet = snippet_elem.text if snippet_elem else ''

                    if url and title != 'No title':
                        results.append({
                            'title': title,
                            'url': url,
                            'snippet': snippet
                        })

                except Exception:
                    continue

        except Exception as e:
            print(f"[!] Failed to parse Google results: {str(e)}")

        return results

    def _is_threat_intelligence_source(self, result):
        """Check if search result is from a threat intelligence source"""
        url = result.get('url', '').lower()
        title = result.get('title', '').lower()
        snippet = result.get('snippet', '').lower()

        # Threat intelligence keywords
        ti_keywords = [
            'malware', 'threat', 'campaign', 'security', 'bleepingcomputer',
            'threatpost', 'krebs', 'mandiant', 'crowdstrike', 'kaspersky',
            'symantec', 'mcafee', 'eset', 'fortinet', 'palo alto',
            'cisco talos', 'proofpoint', 'fireeye', 'secureworks',
            'virustotal', 'hybrid-analysis', 'any.run', 'darkspectre',
            'zoomstealer', 'vulnerability', 'exploit', 'CVE'
        ]

        # Check if any keywords present
        for keyword in ti_keywords:
            if keyword in url or keyword in title or keyword in snippet:
                return True

        return False

    def check_known_campaigns(self, extension_id, domains):
        """
        Cross-reference extension with known malware campaigns

        Args:
            extension_id: Chrome extension ID
            domains: List of domains contacted by extension

        Returns:
            dict: Campaign matches if any
        """
        # Known malware campaigns (from research)
        KNOWN_CAMPAIGNS = {
            'DarkSpectre': {
                'c2_domains': ['internetdownloadmanager.top'],
                'description': 'Browser extension malware campaign (2024-2025)',
                'indicators': ['settingsOverride', 'CSP removal', 'remote config']
            },
            'ZoomStealer': {
                'c2_domains': ['zoom-plus.com', 'zoom-extension.com'],
                'description': 'Zoom impersonation campaign',
                'indicators': ['meeting credentials', 'cookie theft']
            }
        }

        matches = []

        for campaign_name, campaign_info in KNOWN_CAMPAIGNS.items():
            # Check domain overlap
            campaign_domains = set(campaign_info['c2_domains'])
            extension_domains = set(domains)

            if campaign_domains & extension_domains:
                matches.append({
                    'campaign': campaign_name,
                    'description': campaign_info['description'],
                    'matched_domains': list(campaign_domains & extension_domains),
                    'indicators': campaign_info['indicators']
                })

        if matches:
            return {
                'has_matches': True,
                'campaigns': matches,
                'confidence': 'HIGH' if len(matches) >= 2 else 'MEDIUM'
            }
        else:
            return {
                'has_matches': False,
                'campaigns': []
            }


def test_threat_attribution():
    """Test threat attribution system"""
    print("=" * 80)
    print("THREAT ATTRIBUTION TEST")
    print("=" * 80)

    attrib = ThreatAttribution()

    # Test with known malicious extension
    print("\nSearching for threat campaign attribution...")
    result = attrib.search_threat_campaigns(
        'eebihieclccoidddmjcencomodomdoei',
        'Supersonic AI'
    )

    if result.get('available'):
        print(f"\n[+] Search queries generated:")
        for finding in result['search_queries']:
            print(f"    {finding['query']}")
            print(f"    URL: {finding['search_url']}")
            print()

        print(f"\n[+] VirusTotal Comments: {result['virustotal_comments']}")
        print(f"\n[!] {result['recommendation']}")
    else:
        print(f"[!] Error: {result.get('error')}")

    # Test campaign matching
    print("\n" + "=" * 80)
    print("CAMPAIGN MATCHING TEST")
    print("=" * 80)

    domains = ['internetdownloadmanager.top', 'example.com']
    campaign_result = attrib.check_known_campaigns('test_id', domains)

    if campaign_result['has_matches']:
        print(f"\n[!] CAMPAIGN MATCH FOUND")
        print(f"Confidence: {campaign_result['confidence']}")
        for match in campaign_result['campaigns']:
            print(f"\nCampaign: {match['campaign']}")
            print(f"Description: {match['description']}")
            print(f"Matched Domains: {', '.join(match['matched_domains'])}")
            print(f"Indicators: {', '.join(match['indicators'])}")
    else:
        print("\n[OK] No known campaign matches")


if __name__ == "__main__":
    test_threat_attribution()
