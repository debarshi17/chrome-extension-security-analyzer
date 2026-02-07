"""
Browser Extension Downloader
Downloads .crx files from Chrome Web Store and Microsoft Edge Add-ons
"""

import requests
import os
from pathlib import Path
from tqdm import tqdm
import time
from enum import Enum


class BrowserType(Enum):
    """Supported browser extension stores"""
    CHROME = "chrome"
    EDGE = "edge"


class ExtensionDownloader:
    """Downloads browser extensions from Chrome Web Store and Microsoft Edge Add-ons"""

    def __init__(self, download_dir="downloads"):
        self.download_dir = Path(download_dir)
        self.download_dir.mkdir(exist_ok=True)

        # Download URLs for each store
        self.download_urls = {
            BrowserType.CHROME: "https://clients2.google.com/service/update2/crx",
            BrowserType.EDGE: "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
        }

        # Store URLs for info/metadata
        self.store_urls = {
            BrowserType.CHROME: "https://chrome.google.com/webstore/detail/",
            BrowserType.EDGE: "https://microsoftedge.microsoft.com/addons/detail/"
        }

        # User agent to mimic browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
        }

    def download_extension(self, extension_id, browser=BrowserType.CHROME, version="latest"):
        """
        Download a browser extension by its ID

        Args:
            extension_id (str): The extension ID (32-character string)
            browser (BrowserType): Browser store to download from (CHROME or EDGE)
            version (str): Version to download (default: latest)

        Returns:
            Path: Path to downloaded .crx file, or None if failed
        """
        browser_name = browser.value.capitalize()
        print(f"\n[+] Downloading {browser_name} extension: {extension_id}")

        # Build download URL with parameters based on browser
        if browser == BrowserType.CHROME:
            params = {
                'response': 'redirect',
                'prodversion': '120.0',
                'acceptformat': 'crx2,crx3',
                'x': f'id={extension_id}&uc'
            }
        elif browser == BrowserType.EDGE:
            params = {
                'response': 'redirect',
                'x': f'id={extension_id}&installsource=ondemand&uc'
            }
        else:
            print(f"[[X]] Unsupported browser: {browser}")
            return None

        try:
            # Make request with stream=True for large files
            response = requests.get(
                self.download_urls[browser],
                params=params,
                headers=self.headers,
                stream=True,
                timeout=30
            )

            response.raise_for_status()

            # Check if we got a valid CRX file
            content_type = response.headers.get('content-type', '')
            if 'text/html' in content_type.lower():
                print(f"[[X]] Extension not found in {browser_name} store")
                return None

            # Save to file with browser prefix
            prefix = "edge_" if browser == BrowserType.EDGE else ""
            output_path = self.download_dir / f"{prefix}{extension_id}.crx"

            # Get file size if available
            total_size = int(response.headers.get('content-length', 0))

            # Download with progress bar
            with open(output_path, 'wb') as f:
                if total_size:
                    with tqdm(total=total_size, unit='B', unit_scale=True, desc=extension_id) as pbar:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
                                pbar.update(len(chunk))
                else:
                    # No content-length header
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)

            file_size = output_path.stat().st_size

            # Validate file size (CRX files should be at least a few KB)
            if file_size < 1000:
                print(f"[[X]] Downloaded file too small ({file_size} bytes) - extension may not exist")
                output_path.unlink()  # Delete invalid file
                return None

            print(f"[[OK]] Downloaded: {output_path} ({file_size:,} bytes)")

            return output_path

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                print(f"[[X]] Extension not found in {browser_name} store")
            else:
                print(f"[[X]] Download failed: {e}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"[[X]] Download failed: {e}")
            return None
        except Exception as e:
            print(f"[[X]] Unexpected error: {e}")
            return None

    def download_chrome_extension(self, extension_id):
        """Convenience method to download from Chrome Web Store"""
        return self.download_extension(extension_id, BrowserType.CHROME)

    def download_edge_extension(self, extension_id):
        """Convenience method to download from Microsoft Edge Add-ons"""
        return self.download_extension(extension_id, BrowserType.EDGE)

    def detect_browser_store(self, extension_id):
        """
        Try to detect which store an extension belongs to

        Args:
            extension_id (str): The extension ID

        Returns:
            BrowserType or None: Detected browser store
        """
        # Try Chrome first (more common)
        chrome_url = f"https://clients2.google.com/service/update2/crx?response=redirect&prodversion=120.0&x=id%3D{extension_id}%26uc"
        try:
            resp = requests.head(chrome_url, allow_redirects=False, timeout=10)
            if resp.status_code == 302:
                return BrowserType.CHROME
        except:
            pass

        # Try Edge
        edge_url = f"https://edge.microsoft.com/extensionwebstorebase/v1/crx?response=redirect&x=id%3D{extension_id}%26installsource%3Dondemand%26uc"
        try:
            resp = requests.head(edge_url, allow_redirects=False, timeout=10)
            if resp.status_code == 302:
                return BrowserType.EDGE
        except:
            pass

        return None

    def download_multiple(self, extension_ids, browser=BrowserType.CHROME, delay=1):
        """
        Download multiple extensions

        Args:
            extension_ids (list): List of extension IDs
            browser (BrowserType): Browser store to download from
            delay (int): Delay between downloads in seconds

        Returns:
            dict: Mapping of extension_id to download path
        """
        results = {}
        browser_name = browser.value.capitalize()

        print(f"\n[+] Downloading {len(extension_ids)} {browser_name} extensions...")

        for i, ext_id in enumerate(extension_ids, 1):
            print(f"\n[{i}/{len(extension_ids)}]")
            path = self.download_extension(ext_id, browser)
            results[ext_id] = path

            # Rate limiting - be nice to the stores
            if i < len(extension_ids):
                time.sleep(delay)

        # Summary
        successful = sum(1 for p in results.values() if p is not None)
        print(f"\n[+] Download complete: {successful}/{len(extension_ids)} successful")

        return results

    def get_extension_info(self, extension_id, browser=BrowserType.CHROME):
        """
        Get basic info about an extension from its store

        Args:
            extension_id (str): The extension ID
            browser (BrowserType): Browser store to query

        Returns:
            dict: Extension metadata
        """
        store_url = f"{self.store_urls[browser]}{extension_id}"

        try:
            response = requests.get(store_url, headers=self.headers, timeout=10)

            info = {
                'id': extension_id,
                'browser': browser.value,
                'store_url': store_url,
                'available': response.status_code == 200
            }

            return info

        except Exception as e:
            print(f"[[X]] Could not fetch info: {e}")
            return {'id': extension_id, 'browser': browser.value, 'available': False}

    def is_edge_extension(self, extension_id):
        """Check if an extension exists in the Edge Add-ons store"""
        edge_url = f"https://edge.microsoft.com/extensionwebstorebase/v1/crx?response=redirect&x=id%3D{extension_id}%26installsource%3Dondemand%26uc"
        try:
            resp = requests.head(edge_url, allow_redirects=False, timeout=10)
            return resp.status_code == 302
        except:
            return False

    def is_chrome_extension(self, extension_id):
        """Check if an extension exists in the Chrome Web Store"""
        chrome_url = f"https://clients2.google.com/service/update2/crx?response=redirect&prodversion=120.0&x=id%3D{extension_id}%26uc"
        try:
            resp = requests.head(chrome_url, allow_redirects=False, timeout=10)
            return resp.status_code == 302
        except:
            return False


def main():
    """Test the downloader"""

    # Example extension IDs
    chrome_extensions = [
        'cjpalhdlnbpafiamejdnhcphjbkeiagm',  # uBlock Origin (Chrome)
    ]

    edge_extensions = [
        'odfafepnkmbhccpbejgmiehpchacaeak',  # uBlock Origin (Edge)
    ]

    downloader = ExtensionDownloader()

    print("Browser Extension Downloader - Test Mode")
    print("=" * 50)

    # Test Chrome download
    print("\n--- Chrome Web Store ---")
    for ext_id in chrome_extensions:
        path = downloader.download_chrome_extension(ext_id)
        print(f"  Result: {path}")

    # Test Edge download
    print("\n--- Microsoft Edge Add-ons ---")
    for ext_id in edge_extensions:
        path = downloader.download_edge_extension(ext_id)
        print(f"  Result: {path}")

    # Test auto-detection
    print("\n--- Auto-detection Test ---")
    test_id = 'cjpalhdlnbpafiamejdnhcphjbkeiagm'
    detected = downloader.detect_browser_store(test_id)
    print(f"  {test_id}: {detected.value if detected else 'Not found'}")


if __name__ == "__main__":
    main()
