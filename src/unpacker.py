"""
Chrome Extension Unpacker
Extracts and parses .crx files
"""

import zipfile
import json
import shutil
from pathlib import Path

class ExtensionUnpacker:
    """Unpacks Chrome extension .crx files"""
    
    def __init__(self, extract_dir="data/extensions"):
        self.extract_dir = Path(extract_dir)
        self.extract_dir.mkdir(parents=True, exist_ok=True)
    
    def unpack(self, crx_path):
        """
        Unpack a .crx file
        
        Args:
            crx_path (Path or str): Path to .crx file
            
        Returns:
            Path: Directory containing unpacked extension
        """
        crx_path = Path(crx_path)
        
        if not crx_path.exists():
            print(f"[[X]] File not found: {crx_path}")
            return None
        
        print(f"\n[+] Unpacking: {crx_path.name}")
        
        # Create output directory
        extension_id = crx_path.stem
        output_dir = self.extract_dir / extension_id
        
        # Remove existing directory
        if output_dir.exists():
            shutil.rmtree(output_dir)
        
        output_dir.mkdir(parents=True)
        
        try:
            # .crx files are essentially ZIP files with a header
            # We can try to extract them as ZIP
            with zipfile.ZipFile(crx_path, 'r') as zip_ref:
                zip_ref.extractall(output_dir)
            
            print(f"[[OK]] Extracted to: {output_dir}")
            
            # Count files
            file_count = sum(1 for _ in output_dir.rglob('*') if _.is_file())
            print(f"[+] Files extracted: {file_count}")
            
            return output_dir
            
        except zipfile.BadZipFile:
            # CRX format may need header stripped
            print("[!] Attempting to strip CRX header...")
            return self._unpack_with_header_strip(crx_path, output_dir)
        except Exception as e:
            print(f"[[X]] Extraction failed: {e}")
            return None
    
    def _unpack_with_header_strip(self, crx_path, output_dir):
        """
        Unpack CRX by stripping the header first
        
        CRX3 format:
        - Magic number: "Cr24"
        - Version: 3
        - Header data
        - ZIP archive
        """
        try:
            with open(crx_path, 'rb') as f:
                # Read magic number
                magic = f.read(4)
                
                if magic != b'Cr24':
                    print(f"[[X]] Invalid CRX magic number: {magic}")
                    return None
                
                # Read version
                version = int.from_bytes(f.read(4), 'little')
                print(f"[+] CRX version: {version}")
                
                if version == 3:
                    # CRX3 format
                    header_size = int.from_bytes(f.read(4), 'little')
                    f.read(header_size)  # Skip header
                elif version == 2:
                    # CRX2 format
                    pubkey_len = int.from_bytes(f.read(4), 'little')
                    sig_len = int.from_bytes(f.read(4), 'little')
                    f.read(pubkey_len + sig_len)  # Skip public key and signature
                
                # Rest is ZIP data
                zip_data = f.read()
            
            # Write ZIP data to temp file
            temp_zip = output_dir.parent / f"{output_dir.name}_temp.zip"
            with open(temp_zip, 'wb') as f:
                f.write(zip_data)
            
            # Extract ZIP
            with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
                zip_ref.extractall(output_dir)
            
            # Remove temp file
            temp_zip.unlink()
            
            print(f"[[OK]] Extracted to: {output_dir}")
            return output_dir
            
        except Exception as e:
            print(f"[[X]] Header strip failed: {e}")
            return None
    
    def read_manifest(self, extension_dir):
        """
        Read and parse manifest.json
        
        Args:
            extension_dir (Path): Directory containing unpacked extension
            
        Returns:
            dict: Parsed manifest data
        """
        extension_dir = Path(extension_dir)
        manifest_path = extension_dir / "manifest.json"
        
        if not manifest_path.exists():
            print(f"[[X]] manifest.json not found in {extension_dir}")
            return None
        
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest = json.load(f)
            
            print(f"[+] Extension: {manifest.get('name', 'Unknown')}")
            print(f"[+] Version: {manifest.get('version', 'Unknown')}")
            print(f"[+] Manifest version: {manifest.get('manifest_version', 'Unknown')}")
            
            return manifest
            
        except Exception as e:
            print(f"[[X]] Failed to read manifest: {e}")
            return None
    
    def get_file_list(self, extension_dir):
        """
        Get list of all files in the extension
        
        Args:
            extension_dir (Path): Directory containing unpacked extension
            
        Returns:
            list: List of file paths
        """
        extension_dir = Path(extension_dir)
        files = []
        
        for file_path in extension_dir.rglob('*'):
            if file_path.is_file():
                relative_path = file_path.relative_to(extension_dir)
                files.append({
                    'path': str(relative_path),
                    'size': file_path.stat().st_size,
                    'extension': file_path.suffix
                })
        
        return files


def main():
    """Test the unpacker"""
    
    print("Chrome Extension Unpacker - Test Mode")
    print("=" * 50)
    
    unpacker = ExtensionUnpacker()
    
    # Find downloaded .crx files
    download_dir = Path("downloads")
    crx_files = list(download_dir.glob("*.crx"))
    
    if not crx_files:
        print("[!] No .crx files found in downloads/")
        print("[!] Run downloader.py first")
        return
    
    print(f"\n[+] Found {len(crx_files)} extensions")
    
    for crx_path in crx_files:
        # Unpack
        extension_dir = unpacker.unpack(crx_path)
        
        if extension_dir:
            # Read manifest
            manifest = unpacker.read_manifest(extension_dir)
            
            # List files
            files = unpacker.get_file_list(extension_dir)
            print(f"[+] Total files: {len(files)}")
            
            # Show file types
            extensions = {}
            for f in files:
                ext = f['extension'] or 'no_extension'
                extensions[ext] = extensions.get(ext, 0) + 1
            
            print("[+] File types:")
            for ext, count in sorted(extensions.items()):
                print(f"    {ext}: {count}")
        
        print()


if __name__ == "__main__":
    main()