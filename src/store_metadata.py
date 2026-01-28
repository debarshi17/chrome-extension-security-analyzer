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
            # Chrome Web Store URL
            store_url = f"https://chrome.google.com/webstore/detail/{extension_id}"

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

            # Extract metadata from page
            metadata = {
                'available': True,
                'extension_id': extension_id,
                'store_url': store_url
            }

            # Extension name
            title_tag = soup.find('h1', class_='e-f-w')
            if title_tag:
                metadata['name'] = title_tag.text.strip()

            # Author/Publisher
            author_tag = soup.find('a', class_='e-f-Me')
            if author_tag:
                metadata['author'] = author_tag.text.strip()
                metadata['author_url'] = author_tag.get('href', '')
                metadata['author_verified'] = 'verified' in author_tag.get('class', [])

            # User count
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

            # Rating count
            rating_count_tag = soup.find('span', class_='q-N-nd')
            if rating_count_tag:
                count_text = rating_count_tag.text.strip()
                metadata['rating_count'] = int(count_text.replace(',', ''))

            # Description
            description_tag = soup.find('div', class_='C-b-p-j-Pb')
            if description_tag:
                metadata['description'] = description_tag.text.strip()[:500]  # First 500 chars

            # Version
            version_tag = soup.find('span', class_='C-b-p-D-Xe h-C-b-p-D-md')
            if version_tag:
                metadata['version'] = version_tag.text.strip()

            # Last updated
            updated_tag = soup.find('span', class_='C-b-p-D-Xe h-C-b-p-D-xh-hh')
            if updated_tag:
                updated_text = updated_tag.text.strip()
                metadata['last_updated_text'] = updated_text
                metadata['last_updated_date'] = self._parse_date(updated_text)

            # Size
            size_tag = soup.find('span', class_='C-b-p-D-Xe h-C-b-p-D-za')
            if size_tag:
                metadata['size'] = size_tag.text.strip()

            # Privacy policy
            privacy_link = soup.find('a', href=lambda x: x and 'privacy' in x.lower())
            metadata['has_privacy_policy'] = privacy_link is not None
            if privacy_link:
                metadata['privacy_policy_url'] = privacy_link.get('href', '')

            # Chrome warnings
            warning_banner = soup.find('div', class_='webstore-notice-text')
            if warning_banner:
                metadata['chrome_warning'] = warning_banner.text.strip()
                metadata['has_chrome_warning'] = True
            else:
                metadata['has_chrome_warning'] = False

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
