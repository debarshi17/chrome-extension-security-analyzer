"""
Chrome Extension Downloader
Downloads .crx files from Chrome Web Store
"""

import requests
import os
from pathlib import Path
from tqdm import tqdm
import time

class ExtensionDownloader:
    """Downloads Chrome extensions from the Chrome Web Store"""
    
    def __init__(self, download_dir="downloads"):
        self.download_dir = Path(download_dir)
        self.download_dir.mkdir(exist_ok=True)
        
        # Chrome Web Store download URL
        self.download_url = "https://clients2.google.com/service/update2/crx"
        
        # User agent to mimic Chrome browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
    
    def download_extension(self, extension_id, version="latest"):
        """
        Download a Chrome extension by its ID
        
        Args:
            extension_id (str): The Chrome extension ID
            version (str): Version to download (default: latest)
            
        Returns:
            Path: Path to downloaded .crx file, or None if failed
        """
        print(f"\n[+] Downloading extension: {extension_id}")
        
        # Build download URL with parameters
        params = {
            'response': 'redirect',
            'prodversion': '120.0',
            'acceptformat': 'crx2,crx3',
            'x': f'id={extension_id}&uc'
        }
        
        try:
            # Make request with stream=True for large files
            response = requests.get(
                self.download_url,
                params=params,
                headers=self.headers,
                stream=True,
                timeout=30
            )
            
            response.raise_for_status()
            
            # Save to file
            output_path = self.download_dir / f"{extension_id}.crx"
            
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
            print(f"[✓] Downloaded: {output_path} ({file_size:,} bytes)")
            
            return output_path
            
        except requests.exceptions.RequestException as e:
            print(f"[✗] Download failed: {e}")
            return None
        except Exception as e:
            print(f"[✗] Unexpected error: {e}")
            return None
    
    def download_multiple(self, extension_ids, delay=1):
        """
        Download multiple extensions
        
        Args:
            extension_ids (list): List of extension IDs
            delay (int): Delay between downloads in seconds
            
        Returns:
            dict: Mapping of extension_id to download path
        """
        results = {}
        
        print(f"\n[+] Downloading {len(extension_ids)} extensions...")
        
        for i, ext_id in enumerate(extension_ids, 1):
            print(f"\n[{i}/{len(extension_ids)}]")
            path = self.download_extension(ext_id)
            results[ext_id] = path
            
            # Rate limiting - be nice to Chrome Web Store
            if i < len(extension_ids):
                time.sleep(delay)
        
        # Summary
        successful = sum(1 for p in results.values() if p is not None)
        print(f"\n[+] Download complete: {successful}/{len(extension_ids)} successful")
        
        return results
    
    def get_extension_info(self, extension_id):
        """
        Get basic info about an extension from Chrome Web Store
        
        Args:
            extension_id (str): The Chrome extension ID
            
        Returns:
            dict: Extension metadata
        """
        # Note: This is a simplified version
        # Full implementation would scrape the Chrome Web Store page
        
        store_url = f"https://chrome.google.com/webstore/detail/{extension_id}"
        
        try:
            response = requests.get(store_url, headers=self.headers, timeout=10)
            response.raise_for_status()
            
            # Basic info (would need BeautifulSoup to parse properly)
            info = {
                'id': extension_id,
                'store_url': store_url,
                'available': response.status_code == 200
            }
            
            return info
            
        except Exception as e:
            print(f"[✗] Could not fetch info: {e}")
            return {'id': extension_id, 'available': False}


def main():
    """Test the downloader"""
    
    # Example extension IDs
    test_extensions = [
        'cjpalhdlnbpafiamejdnhcphjbkeiagm',  # uBlock Origin
        'nngceckbapebfimnlniiiahkandclblb',  # Bitwarden
    ]
    
    downloader = ExtensionDownloader()
    
    print("Chrome Extension Downloader - Test Mode")
    print("=" * 50)
    
    # Download test extensions
    results = downloader.download_multiple(test_extensions)
    
    # Print results
    print("\nResults:")
    for ext_id, path in results.items():
        status = "✓" if path else "✗"
        print(f"  {status} {ext_id}: {path}")


if __name__ == "__main__":
    main()