#!/usr/bin/env python3
"""
Security utilities for Cyber News Sender
GDPR compliance, encryption, and security headers
"""

import hashlib
import secrets
from typing import Optional, Dict
from functools import wraps
from flask import request, jsonify
from datetime import datetime, timedelta
import json
from .logger import logger


# Rate limiting storage (in production, use Redis)
_rate_limit_store: Dict[str, list] = {}


def hash_email(email: str) -> str:
    """
    Hash email address for privacy (one-way hash).
    Used for analytics without storing plain emails.
    
    Args:
        email: Email address to hash
        
    Returns:
        SHA256 hash of email
    """
    return hashlib.sha256(email.lower().encode('utf-8')).hexdigest()


def generate_consent_token() -> str:
    """
    Generate a secure token for GDPR consent tracking.
    
    Returns:
        Random token string
    """
    return secrets.token_urlsafe(32)


def rate_limit(max_requests: int = 10, window_seconds: int = 60):
    """
    Rate limiting decorator for Flask routes.
    
    Args:
        max_requests: Maximum requests allowed
        window_seconds: Time window in seconds
        
    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client IP
            client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
            
            # Clean old entries
            now = datetime.now()
            if client_ip in _rate_limit_store:
                _rate_limit_store[client_ip] = [
                    ts for ts in _rate_limit_store[client_ip]
                    if (now - ts).total_seconds() < window_seconds
                ]
            else:
                _rate_limit_store[client_ip] = []
            
            # Check rate limit
            if len(_rate_limit_store[client_ip]) >= max_requests:
                logger.warning(f"Rate limit exceeded for IP: {client_ip}")
                return jsonify({
                    'error': 'Rate limit exceeded. Please try again later.'
                }), 429
            
            # Record request
            _rate_limit_store[client_ip].append(now)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def add_security_headers(response):
    """
    Add security headers to Flask response.
    
    Args:
        response: Flask response object
        
    Returns:
        Response with security headers
    """
    # Prevent XSS attacks
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    
    # HTTPS enforcement (in production)
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    return response


class GDPRCompliance:
    """
    GDPR compliance utilities for data management.
    """
    
    @staticmethod
    def can_store_email(email: str, consent_given: bool = True) -> bool:
        """
        Check if email can be stored (GDPR consent check).
        
        Args:
            email: Email address
            consent_given: Whether user gave consent
            
        Returns:
            True if can store, False otherwise
        """
        if not consent_given:
            return False
        
        # Additional checks can be added here
        return True
    
    @staticmethod
    def get_data_retention_days() -> int:
        """
        Get data retention period in days (GDPR compliance).
        
        Returns:
            Number of days to retain data
        """
        return 365  # 1 year retention
    
    @staticmethod
    def should_delete_old_data() -> bool:
        """
        Check if old data should be deleted (GDPR compliance).
        
        Returns:
            True if old data should be deleted
        """
        return True
    
    @staticmethod
    def format_data_export(recipient_data: Dict) -> Dict:
        """
        Format data for GDPR data export request.
        
        Args:
            recipient_data: Recipient data dictionary
            
        Returns:
            Formatted data export
        """
        return {
            'email': recipient_data.get('email'),
            'subscription_date': recipient_data.get('created_at'),
            'active': recipient_data.get('active'),
            'preferences': recipient_data.get('preferences', {}),
            'export_date': datetime.utcnow().isoformat(),
            'data_type': 'subscription_data'
        }


def validate_input(data: Dict, required_fields: list, max_lengths: Optional[Dict] = None) -> tuple[bool, Optional[str]]:
    """
    Validate input data for API endpoints.
    
    Args:
        data: Input data dictionary
        required_fields: List of required field names
        max_lengths: Dictionary of field_name -> max_length
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(data, dict):
        return False, "Invalid input format"
    
    # Check required fields
    for field in required_fields:
        if field not in data or not data[field]:
            return False, f"Missing required field: {field}"
    
    # Check max lengths
    if max_lengths:
        for field, max_len in max_lengths.items():
            if field in data and isinstance(data[field], str):
                if len(data[field]) > max_len:
                    return False, f"Field '{field}' exceeds maximum length of {max_len}"
    
    return True, None


def sanitize_json_input(data: Dict) -> Dict:
    """
    Sanitize JSON input to prevent injection attacks.
    
    Args:
        data: Input data dictionary
        
    Returns:
        Sanitized data dictionary
    """
    sanitized = {}
    for key, value in data.items():
        # Limit key length
        if len(str(key)) > 100:
            continue
        
        # Sanitize value based on type
        if isinstance(value, str):
            # Limit string length
            if len(value) > 10000:
                value = value[:10000]
            # Remove null bytes
            value = value.replace('\x00', '')
        elif isinstance(value, (int, float, bool)):
            pass  # Numbers and booleans are safe
        elif isinstance(value, list):
            # Recursively sanitize list items
            value = [sanitize_json_input({'item': v})['item'] if isinstance(v, dict) else v for v in value[:100]]
        elif isinstance(value, dict):
            # Recursively sanitize nested dicts
            value = sanitize_json_input(value)
        
        sanitized[key] = value
    
    return sanitized
