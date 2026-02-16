"""
Chrome Web Store Metadata Collector
Fetches extension metadata from Chrome Web Store before analysis
"""

import requests
import json
import re
from datetime import datetime
from bs4 import BeautifulSoup


class StoreMetadata:
    """Collect Chrome Web Store metadata for context"""

    def __init__(self):
        """Initialize metadata collector"""
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

    def fetch_metadata(self, extension_id):
        """
        Fetch complete Chrome Web Store metadata

        Args:
            extension_id: Chrome extension ID

        Returns:
            dict: Complete store metadata
        """
        try:
            # Chrome Web Store URL (new store at chromewebstore.google.com; old chrome.google.com uses different HTML)
            store_url = f"https://chromewebstore.google.com/detail/{extension_id}"

            headers = {
                'User-Agent': self.user_agent,
                'Accept-Language': 'en-US,en;q=0.9'
            }

            response = requests.get(store_url, headers=headers, timeout=10)

            if response.status_code != 200:
                return {
                    'available': False,
                    'error': f'Store returned status {response.status_code}'
                }

            soup = BeautifulSoup(response.text, 'html.parser')
            text = response.text

            # Extract metadata from page
            metadata = {
                'available': True,
                'extension_id': extension_id,
                'store_url': store_url
            }

            # ----- New Chrome Web Store (chromewebstore.google.com) -----
            # Page may be app-shell; try embedded JSON and regex fallbacks first.
            self._fill_from_embedded_json_or_regex(metadata, text, extension_id)
            # Fill from HTML selectors (old store or new store DOM)
            self._fill_from_dom(metadata, soup)
            # Privacy and warnings (DOM or regex)
            privacy_link = soup.find('a', href=lambda x: x and 'privacy' in (x or '').lower())
            metadata['has_privacy_policy'] = privacy_link is not None
            if privacy_link:
                metadata['privacy_policy_url'] = privacy_link.get('href', '')
            if not metadata.get('has_privacy_policy') and re.search(r'privacy\s*policy', text, re.I):
                metadata['has_privacy_policy'] = True
            warning_banner = soup.find('div', class_='webstore-notice-text')
            if warning_banner:
                metadata['chrome_warning'] = warning_banner.text.strip()
                metadata['has_chrome_warning'] = True
            else:
                metadata['has_chrome_warning'] = False

            if metadata.get('name') and ' - Chrome Web Store' in metadata['name']:
                metadata['name'] = metadata['name'].replace(' - Chrome Web Store', '').strip()

            # Store listing flags (featured, trader)
            metadata['featured'] = bool(re.search(r'\bFeatured\b', text))
            metadata['trader'] = bool(re.search(r'\bTrader\b', text))

            # Calculate risk signals
            metadata['risk_signals'] = self._calculate_risk_signals(metadata)

            return metadata

        except Exception as e:
            return {
                'available': False,
                'error': f'Metadata fetch failed: {str(e)}'
            }

    def _parse_user_count(self, user_text):
        """Parse user count from text like '1,000+ users'"""
        try:
            # Remove text, keep numbers
            num_text = re.sub(r'[^\d.,]', '', user_text).replace(',', '')

            if '+' in user_text:
                # Minimum count
                return int(num_text)
            else:
                return int(num_text)
        except:
            return 0

    def _parse_date(self, date_text):
        """Parse date from Chrome Web Store format"""
        try:
            # Examples: "January 15, 2026", "December 2025"
            # For now, return as-is (could be enhanced)
            return date_text
        except:
            return None

    def _fill_from_embedded_json_or_regex(self, metadata, text, extension_id):
        """Fill metadata from embedded JSON or regex on page text (new store)."""
        # Try embedded JSON (common keys used by CWS / Material-style apps)
        for pattern in (
            r'"title"\s*:\s*"([^"]+)"',
            r'"name"\s*:\s*"([^"]+)"',
            r'"creator"\s*:\s*"([^"]+)"',
            r'"developerName"\s*:\s*"([^"]+)"',
            r'"developer"\s*:\s*\{[^}]*"name"\s*:\s*"([^"]+)"',
            r'"author"\s*:\s*"([^"]+)"',
            r'"userCount"\s*:\s*["]?([\d,]+)',
            r'"numUsers"\s*:\s*["]?([\d,]+)',
            r'"version"\s*:\s*"([^"]+)"',
        ):
            m = re.search(pattern, text)
            if m:
                val = m.group(1).strip()
                if 'title' in pattern or (pattern.startswith(r'"name"') and not metadata.get('name')):
                    if not metadata.get('name') and len(val) < 200:
                        metadata['name'] = val
                if 'creator' in pattern or 'developer' in pattern or 'author' in pattern:
                    if not metadata.get('author') and len(val) < 200:
                        metadata['author'] = val
                if 'userCount' in pattern or 'numUsers' in pattern:
                    if not metadata.get('user_count_text'):
                        metadata['user_count_text'] = f'{val}+ users'
                        metadata['user_count'] = self._parse_user_count(metadata['user_count_text'])
                if 'version' in pattern and not metadata.get('version'):
                    metadata['version'] = val
        # Regex fallbacks from visible page text (new store copy)
        if not metadata.get('user_count_text'):
            mu = re.search(r'([\d,]+)\s*users', text)
            if mu:
                metadata['user_count_text'] = mu.group(0).strip()
                metadata['user_count'] = self._parse_user_count(metadata['user_count_text'])
        if not metadata.get('author'):
            # New store: developer name often appears as "Name Ltd.<br>Address" or "Name Inc.<br>"
            md = re.search(r'([A-Za-z][A-Za-z0-9\s,\.\-]+(?:Ltd\.|Inc\.|LLC|Limited))\s*<br\s*/?>', text)
            if md:
                author = re.sub(r'\s+', ' ', md.group(1).strip())
                if len(author) < 150 and 'Dashboard' not in author:
                    metadata['author'] = author
            if not metadata.get('author'):
                md = re.search(r'Developer\s*[:\s]*([^\n<]+)', text)
                if md:
                    author = md.group(1).strip().split('\n')[0].strip()
                    author = re.sub(r'\s+', ' ', author)
                    if re.search(r'\b(Street|House|Dublin|D04)\b', author):
                        author = re.sub(r'\s+(Gordon|Barrow|Street|Dublin|D04).*', '', author, flags=re.I).strip()
                    if len(author) < 150 and not author.startswith('http') and 'Dashboard' not in author:
                        metadata['author'] = author
        if not metadata.get('version'):
            mv = re.search(r'Version\s*[:\s]*(\d+\.\d+(?:\.\d+)?)', text)
            if mv:
                metadata['version'] = mv.group(1)
            if not metadata.get('version'):
                mv = re.search(r'>Version</div><div>([^<]+)</div>', text)
                if mv:
                    metadata['version'] = mv.group(1).strip()
            if not metadata.get('version'):
                mv = re.search(r'(\d+\.\d+\.\d+)</div></li><li[^>]*><div[^>]*>Updated', text)
                if mv:
                    metadata['version'] = mv.group(1)
        if not metadata.get('last_updated_text'):
            mo = re.search(r'Updated\s*[:\s]*([A-Za-z]+\s+\d+,?\s+\d{4})', text)
            if mo:
                metadata['last_updated_text'] = mo.group(1).strip()
            if not metadata.get('last_updated_text'):
                mo = re.search(r'>Updated</div><div>([^<]+)</div>', text)
                if mo:
                    metadata['last_updated_text'] = mo.group(1).strip()
        if not metadata.get('size'):
            ms = re.search(r'Size\s*[:\s]*([\d.]+\s*[KMG]?i?B)', text, re.I)
            if ms:
                metadata['size'] = ms.group(1).strip()
            if not metadata.get('size'):
                ms = re.search(r'>Size</div><div>([^<]+)</div>', text)
                if ms:
                    metadata['size'] = ms.group(1).strip()
        # Developer info from embedded data array (most reliable on new store)
        if not metadata.get('author') or not metadata.get('author_verified'):
            dev_match = re.search(
                r'\["([^"]*@[^"]+)",'           # developer email
                r'(?:"[^"]*"|null),'             # address
                r'(?:null|\d+),'                 # field2
                r'(\d+|null),'                   # verified flag
                r'(?:null|\d+),'                 # field4
                r'"([^"]+)",'                    # developer id
                r'"([^"]+)"',                    # developer name
                text
            )
            if dev_match:
                if not metadata.get('author'):
                    metadata['author'] = dev_match.group(4)
                metadata['author_verified'] = dev_match.group(2) == '1'
        # og:title / meta title
        if not metadata.get('name'):
            mt = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']', text, re.I)
            if not mt:
                mt = re.search(r'<title[^>]*>([^<]+)</title>', text, re.I)
            if mt:
                metadata['name'] = mt.group(1).strip()[:200]

    def _fill_from_dom(self, metadata, soup):
        """Fill metadata from DOM selectors (old and new store)."""
        # Extension name (old: h1.e-f-w; new: may use h1 or different class)
        if not metadata.get('name'):
            title_tag = soup.find('h1', class_='e-f-w')
            if title_tag:
                metadata['name'] = title_tag.text.strip()
            if not metadata.get('name'):
                h1 = soup.find('h1')
                if h1 and h1.get_text(strip=True):
                    metadata['name'] = h1.get_text(strip=True)[:200]
        # Author (old: a.e-f-Me; new: link or span near "Developer")
        if not metadata.get('author'):
            author_tag = soup.find('a', class_='e-f-Me')
            if author_tag:
                metadata['author'] = author_tag.text.strip()
                metadata['author_url'] = author_tag.get('href', '')
                metadata['author_verified'] = 'verified' in author_tag.get('class', [])
        if not metadata.get('author'):
            author_tag = soup.find('a', href=re.compile(r'/collection/|/developer/'))
            if author_tag:
                atext = author_tag.get_text(strip=True)[:200]
                if atext and 'dashboard' not in atext.lower() and 'opens' not in atext.lower():
                    metadata['author'] = atext
        if not metadata.get('author_verified'):
            metadata['author_verified'] = self._detect_verified_badge(soup, text)
        # User count (old: span.e-f-ih)
        if not metadata.get('user_count_text'):
            user_count_tag = soup.find('span', class_='e-f-ih')
            if user_count_tag:
                user_text = user_count_tag.text.strip()
                metadata['user_count_text'] = user_text
                metadata['user_count'] = self._parse_user_count(user_text)
        # Rating
        rating_tag = soup.find('div', class_='rsw-stars')
        if rating_tag:
            rating_style = rating_tag.get('style', '')
            width_match = re.search(r'width:\s*(\d+)%', rating_style)
            if width_match:
                width_percent = int(width_match.group(1))
                metadata['rating'] = round((width_percent / 100) * 5, 1)
        rating_count_tag = soup.find('span', class_='q-N-nd')
        if rating_count_tag:
            count_text = rating_count_tag.text.strip()
            try:
                metadata['rating_count'] = int(count_text.replace(',', ''))
            except ValueError:
                pass
        # Description, version, updated, size (old selectors)
        description_tag = soup.find('div', class_='C-b-p-j-Pb')
        if description_tag and not metadata.get('description'):
            metadata['description'] = description_tag.text.strip()[:500]
        version_tag = soup.find('span', class_='C-b-p-D-Xe h-C-b-p-D-md')
        if version_tag and not metadata.get('version'):
            metadata['version'] = version_tag.text.strip()
        updated_tag = soup.find('span', class_='C-b-p-D-Xe h-C-b-p-D-xh-hh')
        if updated_tag and not metadata.get('last_updated_text'):
            metadata['last_updated_text'] = updated_tag.text.strip()
            metadata['last_updated_date'] = self._parse_date(metadata['last_updated_text'])
        size_tag = soup.find('span', class_='C-b-p-D-Xe h-C-b-p-D-za')
        if size_tag and not metadata.get('size'):
            metadata['size'] = size_tag.text.strip()

    def _detect_verified_badge(self, soup, text):
        """
        Detect the verified publisher badge on the Chrome Web Store page.

        The new CWS (chromewebstore.google.com) embeds developer metadata in
        a serialized array. The developer info block follows the pattern:
            ["email@dev.com", "address", null, VERIFIED_FLAG, null, "dev-id", "Dev Name", ...]
        where VERIFIED_FLAG = 1 for verified publishers, null otherwise.
        """
        # Strategy 1 (primary): Parse the embedded developer data array
        # Pattern: [email, address, null, VERIFIED_FLAG, null, dev_id, dev_name]
        m = re.search(
            r'\["([^"]*@[^"]+)",'           # developer email
            r'(?:"[^"]*"|null),'             # address (string or null)
            r'(?:null|\d+),'                 # field2
            r'(\d+|null),'                   # VERIFIED FLAG (1 = verified)
            r'(?:null|\d+),'                 # field4
            r'"([^"]+)",'                    # developer id
            r'"([^"]+)"',                    # developer name
            text
        )
        if m:
            verified_flag = m.group(2)
            if verified_flag == '1':
                return True
            return False

        # Strategy 2: Fallback — embedded JSON fields
        json_patterns = [
            r'"isVerified"\s*:\s*true',
            r'"verified"\s*:\s*true',
            r'"developerVerified"\s*:\s*true',
        ]
        for pattern in json_patterns:
            if re.search(pattern, text, re.I):
                return True

        # Strategy 3: DOM attributes (aria-label, class)
        if soup.find(attrs={'aria-label': re.compile(r'verified', re.I)}):
            return True
        if soup.find(class_=re.compile(r'verif', re.I)):
            return True

        # Strategy 4: Plain text markers
        if re.search(r'Verified\s+(?:developer|publisher)', text, re.I):
            return True

        return False

    def _calculate_risk_signals(self, metadata):
        """
        Calculate risk signals from store metadata

        Returns:
            dict: Risk assessment based on store data
        """
        signals = {
            'abandoned': False,
            'new_extension': False,
            'low_adoption': False,
            'policy_violation': False,
            'unverified_author': False,
            'no_privacy_policy': False
        }

        # Check if abandoned (old version, Chrome warning)
        if metadata.get('has_chrome_warning'):
            signals['policy_violation'] = True

        # Check adoption
        user_count = metadata.get('user_count', 0)
        if user_count < 100:
            signals['low_adoption'] = True

        # Check author verification
        if not metadata.get('author_verified', False):
            signals['unverified_author'] = True

        # Check privacy policy
        if not metadata.get('has_privacy_policy', False):
            signals['no_privacy_policy'] = True

        return signals


def test_store_metadata():
    """Test Chrome Web Store metadata fetcher"""
    print("=" * 80)
    print("CHROME WEB STORE METADATA TEST")
    print("=" * 80)

    metadata = StoreMetadata()

    # Test with real extension
    extension_id = 'eebihieclccoidddmjcencomodomdoei'

    print(f"\nFetching metadata for extension: {extension_id}")
    print("(This may take a few seconds...)\n")

    result = metadata.fetch_metadata(extension_id)

    if result.get('available'):
        print(f"[+] Metadata fetched successfully\n")
        print(f"Name: {result.get('name', 'Unknown')}")
        print(f"Author: {result.get('author', 'Unknown')}")
        print(f"Author Verified: {result.get('author_verified', False)}")
        print(f"Users: {result.get('user_count_text', 'Unknown')}")
        print(f"Rating: {result.get('rating', 'N/A')} ({result.get('rating_count', 0)} ratings)")
        print(f"Version: {result.get('version', 'Unknown')}")
        print(f"Last Updated: {result.get('last_updated_text', 'Unknown')}")
        print(f"Size: {result.get('size', 'Unknown')}")
        print(f"Privacy Policy: {result.get('has_privacy_policy', False)}")
        print(f"Chrome Warning: {result.get('has_chrome_warning', False)}")

        if result.get('chrome_warning'):
            print(f"\n[!] WARNING: {result['chrome_warning']}")

        print(f"\n--- Risk Signals ---")
        risk_signals = result.get('risk_signals', {})
        for signal, value in risk_signals.items():
            if value:
                print(f"  [!] {signal}: {value}")

        if not any(risk_signals.values()):
            print("  [OK] No immediate risk signals from store metadata")

    else:
        print(f"[!] Error: {result.get('error')}")


if __name__ == "__main__":
    test_store_metadata()
