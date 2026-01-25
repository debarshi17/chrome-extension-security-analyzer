"""
Utility functions for the analyzer
"""

import json
from pathlib import Path
from datetime import datetime
import hashlib

def calculate_file_hash(file_path, algorithm='sha256'):
    """Calculate hash of a file"""
    hash_func = hashlib.new(algorithm)
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()

def save_json(data, file_path):
    """Save data to JSON file"""
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def load_json(file_path):
    """Load data from JSON file"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def get_timestamp():
    """Get current timestamp"""
    return datetime.now().isoformat()

def format_bytes(bytes_size):
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024
    return f"{bytes_size:.2f} TB"