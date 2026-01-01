"""
Normalization Module
Handles IoC type detection, validation, and normalization
"""

import re
import ipaddress
import logging
from typing import Tuple, Optional

class IoCNormalizer:
    """Handles IoC normalization and type detection"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Regex patterns for validation
        self.hash_patterns = {
            'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
            'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
            'sha256': re.compile(r'^[a-fA-F0-9]{64}$')
        }
    
    def is_ip(self, value: str) -> bool:
        """Check if value is a valid IP address"""
        try:
            ipaddress.ip_address(value.strip())
            return True
        except ValueError:
            return False
    
    def is_hash(self, value: str) -> bool:
        """Check if value is a hash"""
        value = value.strip()
        for pattern in self.hash_patterns.values():
            if pattern.match(value):
                return True
        return False
    
    def is_url(self, value: str) -> bool:
        """Check if value is a URL"""
        value = value.strip()
        return value.startswith(('http://', 'https://'))
    
    def is_domain(self, value: str) -> bool:
        """Check if value is a domain"""
        value = value.strip()
        if self.is_url(value) or self.is_ip(value):
            return False
        return '.' in value and len(value) <= 253 and not value.startswith('.')
    
    def is_email(self, value: str) -> bool:
        """Check if value is an email"""
        value = value.strip()
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return email_pattern.match(value) is not None
    
    def detect_type(self, value: str) -> str:
        """Detect IoC type with priority order"""
        if not value:
            return "Unknown"
        
        # Priority order: IP, Hash, URL, Email, Domain
        if self.is_ip(value):
            return "IP"
        if self.is_hash(value):
            return "Hash"
        if self.is_url(value):
            return "URL"
        if self.is_email(value):
            return "Email"
        if self.is_domain(value):
            return "Domain"
        
        return "Unknown"
    
    def normalize_indicator(self, indicator: str) -> str:
        """Normalize indicator based on type"""
        indicator = indicator.strip()
        
        # URL normalization
        if self.is_url(indicator):
            return indicator.lower()
        
        # Domain normalization
        if self.is_domain(indicator):
            return indicator.lower()
        
        # Hash normalization
        if self.is_hash(indicator):
            return indicator.lower()
        
        # IP normalization
        if self.is_ip(indicator):
            try:
                return str(ipaddress.ip_address(indicator))
            except ValueError:
                return indicator
        
        return indicator
    
    def normalize_ioc(self, raw_indicator: str, source: str, 
                     confidence: str = "medium", threat_level: str = "medium",
                     metadata: dict = None) -> dict:
        """Normalize a complete IoC"""
        normalized_indicator = self.normalize_indicator(raw_indicator)
        ioc_type = self.detect_type(normalized_indicator)
        
        return {
            'indicator': normalized_indicator,
            'type': ioc_type,
            'source': source,
            'confidence': confidence,
            'threat_level': threat_level,
            'metadata': metadata or {},
            'date_collected': self._get_timestamp()
        }
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow().isoformat()
    
    def validate_ioc(self, ioc: dict) -> bool:
        """Validate IoC structure"""
        required_fields = ['indicator', 'type', 'source']
        return all(field in ioc for field in required_fields)

