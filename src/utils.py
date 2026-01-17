#!/usr/bin/env python3
"""
Utility functions for Cyber News Sender
Common functions to avoid code duplication
"""

import re
import hashlib
from typing import Optional, List
from urllib.parse import urlparse, urlunparse
from datetime import datetime
import html


# CVE validation pattern - centralized
CVE_PATTERN = re.compile(r'^CVE-(\d{4})-(\d{4,7})$', re.IGNORECASE)

# Email validation pattern
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


def is_valid_cve(cve: str) -> bool:
    """
    Validate CVE format strictly: CVE-YYYY-NNNNN where YYYY is 1999-2099 and NNNNN is 4-7 digits.
    
    Args:
        cve: CVE string to validate
        
    Returns:
        True if valid CVE format, False otherwise
    """
    if not cve or not isinstance(cve, str):
        return False
    
    cve = cve.upper().strip()
    
    # Must start with CVE-
    if not cve.startswith('CVE-'):
        return False
    
    # Use strict pattern matching
    match = CVE_PATTERN.match(cve)
    if not match:
        return False
    
    year = int(match.group(1))
    number = match.group(2)
    
    # Year should be between 1999 and 2099 (reasonable range)
    if year < 1999 or year > 2099:
        return False
    
    # Number should be exactly 4-7 digits
    if len(number) < 4 or len(number) > 7:
        return False
    
    # Ensure the full CVE matches exactly (no extra characters)
    expected_format = f"CVE-{year:04d}-{number}"
    if cve != expected_format:
        return False
    
    return True


def validate_email(email: str) -> bool:
    """
    Validate email address format.
    
    Args:
        email: Email string to validate
        
    Returns:
        True if valid email format, False otherwise
    """
    if not email or not isinstance(email, str):
        return False
    
    email = email.strip().lower()
    
    # Basic format check
    if not EMAIL_PATTERN.match(email):
        return False
    
    # Additional checks
    if len(email) > 255:  # RFC 5321 limit
        return False
    
    # Check for common invalid patterns
    if email.startswith('.') or email.endswith('.'):
        return False
    
    if '..' in email:
        return False
    
    return True


def sanitize_email(email: str) -> Optional[str]:
    """
    Sanitize and normalize email address.
    
    Args:
        email: Email string to sanitize
        
    Returns:
        Normalized email or None if invalid
    """
    if not email:
        return None
    
    email = email.strip().lower()
    
    if not validate_email(email):
        return None
    
    return email


def sanitize_string(text: str, max_length: Optional[int] = None) -> str:
    """
    Sanitize string input to prevent XSS and injection attacks.
    
    Args:
        text: String to sanitize
        max_length: Maximum length (None for no limit)
        
    Returns:
        Sanitized string
    """
    if not text:
        return ""
    
    if not isinstance(text, str):
        text = str(text)
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    # Truncate if needed
    if max_length and len(text) > max_length:
        text = text[:max_length]
    
    return text.strip()


def escape_html(text: str) -> str:
    """
    Escape HTML special characters to prevent XSS.
    
    Args:
        text: String to escape
        
    Returns:
        HTML-escaped string
    """
    if not text:
        return ""
    
    return html.escape(str(text))


def normalize_url(url: str) -> str:
    """
    Normalize URL to ensure consistent comparison.
    
    Args:
        url: URL string to normalize
        
    Returns:
        Normalized URL string
    """
    if not url:
        return ""
    
    try:
        parsed = urlparse(url)
        
        # Remove common tracking parameters
        query_params = []
        if parsed.query:
            for param in parsed.query.split('&'):
                if param and not param.startswith(('utm_', 'ref=', 'fbclid=', 'gclid=')):
                    query_params.append(param)
        
        clean_query = '&'.join(sorted(query_params))
        
        # Reconstruct URL without fragment and with sorted query
        normalized_url = urlunparse(parsed._replace(query=clean_query, fragment=''))
        
        # Remove trailing slash if not root
        if normalized_url.endswith('/') and normalized_url != f"{parsed.scheme}://{parsed.netloc}/":
            normalized_url = normalized_url.rstrip('/')
        
        return normalized_url.lower()
    except Exception:
        return url.lower().strip()


def get_content_hash(url: str, title: str) -> str:
    """
    Generate hash for duplicate detection.
    
    Args:
        url: Article URL
        title: Article title
        
    Returns:
        SHA256 hash hex string
    """
    content = f"{normalize_url(url)}{sanitize_string(title)}".lower().strip()
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def format_date(date_obj: datetime, format_str: str = "%B %d, %Y") -> str:
    """
    Format datetime object to string.
    
    Args:
        date_obj: Datetime object
        format_str: Format string
        
    Returns:
        Formatted date string
    """
    if not date_obj:
        return ""
    
    try:
        return date_obj.strftime(format_str)
    except Exception:
        return str(date_obj)


def parse_date(date_str: str) -> Optional[datetime]:
    """
    Parse date string to datetime object.
    
    Args:
        date_str: Date string in various formats
        
    Returns:
        Datetime object or None if parsing fails
    """
    if not date_str:
        return None
    
    # Common date formats
    formats = [
        '%Y-%m-%d',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%dT%H:%M:%SZ',
        '%a, %d %b %Y %H:%M:%S %z',
        '%a, %d %b %Y %H:%M:%S %Z',
        '%d %b %Y',
        '%a, %d %b %Y'
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    
    # Try ISO format
    try:
        if 'T' in date_str:
            date_str = date_str.replace('Z', '+00:00')
        return datetime.fromisoformat(date_str)
    except ValueError:
        pass
    
    return None


def validate_url(url: str) -> bool:
    """
    Validate URL format.
    
    Args:
        url: URL string to validate
        
    Returns:
        True if valid URL, False otherwise
    """
    if not url:
        return False
    
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except Exception:
        return False


def sanitize_url(url: str) -> Optional[str]:
    """
    Sanitize and validate URL.
    
    Args:
        url: URL string to sanitize
        
    Returns:
        Sanitized URL or None if invalid
    """
    if not url:
        return None
    
    url = url.strip()
    
    if not validate_url(url):
        return None
    
    # Prevent javascript: and data: URLs
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return None
    
    return url
