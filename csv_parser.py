"""
CSV Parser Utility Module
Handles parsing CSV files and extracting URLs from various column name variations.
"""
import csv
import io
from urllib.parse import urlparse
from typing import List, Dict, Tuple


# Supported column name variations for URL extraction
URL_COLUMN_NAMES = [
    'url', 'URL', 'website', 'Website', 'domain', 'Domain',
    'company_url', 'Company_URL', 'site', 'Site', 'link', 'Link',
    'website_url', 'Website_URL', 'domain_name', 'Domain_Name',
    'company_website', 'Company_Website', 'web_address', 'Web_Address'
]


def validate_url(url: str) -> bool:
    """
    Validate if a string is a valid URL format.
    
    Args:
        url: String to validate as URL
    
    Returns:
        True if valid URL format, False otherwise
    """
    if not url or not isinstance(url, str):
        return False
    
    url = url.strip()
    if not url:
        return False
    
    # Add protocol if missing for validation
    if not url.startswith(('http://', 'https://')):
        test_url = 'https://' + url
    else:
        test_url = url
    
    try:
        result = urlparse(test_url)
        # Check if we have at least a netloc (domain)
        return bool(result.netloc) or bool(result.path)
    except:
        return False


def normalize_url(url: str) -> str:
    """
    Normalize URL by adding protocol if missing.
    
    Args:
        url: URL string to normalize
    
    Returns:
        Normalized URL with protocol
    """
    if not url:
        return url
    
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        return 'https://' + url
    return url


def find_url_column(headers: List[str]) -> int:
    """
    Find the index of the URL column in CSV headers.
    
    Args:
        headers: List of header strings
    
    Returns:
        Index of URL column, or -1 if not found
    """
    headers_lower = [h.strip().lower() for h in headers]
    url_column_names_lower = [name.lower() for name in URL_COLUMN_NAMES]
    
    for idx, header in enumerate(headers_lower):
        if header in url_column_names_lower:
            return idx
        
        # Check if header contains any URL-related keywords
        for url_keyword in ['url', 'website', 'domain', 'link', 'site']:
            if url_keyword in header:
                return idx
    
    # If no URL column found, check first column
    return 0


def parse_csv_file(file_content: bytes) -> Tuple[List[str], Dict]:
    """
    Parse CSV file and extract URLs.
    
    Args:
        file_content: CSV file content as bytes
    
    Returns:
        Tuple of (list of URLs, metadata dictionary)
    
    Raises:
        ValueError: If CSV format is invalid or no URLs found
    """
    try:
        # Decode file content
        try:
            content_str = file_content.decode('utf-8')
        except UnicodeDecodeError:
            # Try with different encodings
            try:
                content_str = file_content.decode('latin-1')
            except:
                content_str = file_content.decode('utf-8', errors='ignore')
        
        # Create StringIO object for CSV reader
        csv_file = io.StringIO(content_str)
        
        # Detect delimiter
        sample = content_str[:1024]
        sniffer = csv.Sniffer()
        delimiter = sniffer.sniff(sample).delimiter
        
        # Read CSV
        reader = csv.reader(csv_file, delimiter=delimiter)
        
        # Read headers
        try:
            headers = next(reader)
        except StopIteration:
            raise ValueError("CSV file is empty")
        
        if not headers:
            raise ValueError("CSV file has no headers")
        
        # Find URL column
        url_column_idx = find_url_column(headers)
        
        # Extract URLs
        urls = []
        row_number = 1  # Start from 1 (after header)
        
        for row in reader:
            row_number += 1
            if not row:  # Skip empty rows
                continue
            
            # Get URL from the identified column
            if url_column_idx < len(row):
                url_candidate = row[url_column_idx].strip()
                
                if url_candidate and validate_url(url_candidate):
                    normalized_url = normalize_url(url_candidate)
                    urls.append(normalized_url)
        
        if not urls:
            raise ValueError("No valid URLs found in CSV file")
        
        # Prepare metadata
        metadata = {
            'filename': 'uploaded_file.csv',  # Will be set by caller
            'total_rows': row_number - 1,
            'url_count': len(urls),
            'headers': headers,
            'url_column': headers[url_column_idx] if url_column_idx < len(headers) else 'Unknown',
            'url_column_index': url_column_idx
        }
        
        return urls, metadata
    
    except csv.Error as e:
        raise ValueError(f"Invalid CSV format: {str(e)}")
    except Exception as e:
        raise ValueError(f"Error parsing CSV file: {str(e)}")


def validate_csv_file(file_content: bytes, filename: str) -> Tuple[bool, str, Dict]:
    """
    Validate CSV file and return parsed data.
    
    Args:
        file_content: CSV file content as bytes
        filename: Original filename
    
    Returns:
        Tuple of (is_valid, error_message, data_dict)
        data_dict contains 'urls' and 'metadata' if valid
    """
    try:
        urls, metadata = parse_csv_file(file_content)
        metadata['filename'] = filename
        
        return True, "", {
            'urls': urls,
            'metadata': metadata
        }
    except ValueError as e:
        return False, str(e), {}
    except Exception as e:
        return False, f"Unexpected error: {str(e)}", {}

