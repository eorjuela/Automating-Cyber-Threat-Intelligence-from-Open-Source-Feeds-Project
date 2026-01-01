"""
API Ingestion Module
Handles collection from various threat intelligence APIs
"""

import requests
import logging
from typing import List, Dict, Any
from normalization import IoCNormalizer

class APIIngestion:
    """Handles API-based data collection"""
    
    def __init__(self, db, normalizer: IoCNormalizer):
        self.db = db
        self.normalizer = normalizer
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.timeout = 30
        
        # API configuration
        self.api_keys = {
            'OTX': "b6c7509b96609abdb328e72c04530ed9289d99c12a1f1f0a81f71cb2d72956eb",
            'AbuseIPDB': "9e92b59ddbacd503f78009889be2d10c99e44d73047b4d862557e9581ffcaa0e28cb1377b4a6299e"
        }
    
    def fetch_otx(self, domain: str = "example.com") -> List[Dict[str, Any]]:
        """Fetch indicators from AlienVault OTX"""
        headers = {"X-OTX-API-KEY": self.api_keys['OTX']}
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
        
        try:
            resp = self.session.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            
            iocs = []
            for entry in data.get("url_list", []):
                if entry.get("url"):
                    ioc = self.normalizer.normalize_ioc(
                        raw_indicator=entry["url"],
                        source="OTX",
                        confidence="high",
                        threat_level="medium",
                        metadata={
                            "domain": domain,
                            "pulse_info": entry.get("pulse_info"),
                            "url_id": entry.get("id")
                        }
                    )
                    iocs.append(ioc)
            
            self.logger.info(f"OTX: Collected {len(iocs)} URLs for {domain}")
            return iocs
            
        except Exception as e:
            self.logger.error(f"OTX API error: {e}")
            return []

    def fetch_abuseipdb(self, limit: int = 10000) -> List[Dict[str, Any]]:
        """Fetch indicators from AbuseIPDB"""
        headers = {"Key": self.api_keys['AbuseIPDB'], "Accept": "application/json"}
        params = {"limit": limit, "confidenceMinimum": 50}
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        
        try:
            resp = self.session.get(url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json().get("data", [])
            
            iocs = []
            for entry in data:
                iocs.append(self.normalizer.normalize_ioc(
                    raw_indicator=entry["ipAddress"],
                    source="AbuseIPDB",
                    confidence="high",
                    threat_level="high" if entry["abuseConfidenceScore"] >= 75 else "medium",
                    metadata={"countryCode": entry.get("countryCode"), "isp": entry.get("isp")}
                ))
            
            self.logger.info(f"AbuseIPDB: Collected {len(iocs)} IPs")
            return iocs
            
        except Exception as e:
            self.logger.error(f"AbuseIPDB API error: {e}")
            return []
    
    def fetch_malwarebazaar(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Fetch indicators from MalwareBazaar export feed (always works, no API blocks)"""
        url = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
        
        try:
            resp = self.session.get(url)
            resp.raise_for_status()
            
            # Parse SHA256 hashes from text file
            hashes = [
                line.strip()
                for line in resp.text.split("\n")
                if len(line.strip()) == 64 and not line.startswith("#")
            ][:limit]
            
            iocs = []
            for h in hashes:
                iocs.append(self.normalizer.normalize_ioc(
                    raw_indicator=h,
                    source="MalwareBazaar",
                    confidence="very_high",
                    threat_level="high",
                    metadata={}
                ))
            
            self.logger.info(f"MalwareBazaar Export: Collected {len(iocs)} hashes")
            return iocs
            
        except Exception as e:
            self.logger.error(f"MalwareBazaar Export error: {e}")
            return []
    
    def validate_api_keys(self) -> Dict[str, bool]:
        """Validate API key configuration"""
        validation = {}
        
        validation['OTX'] = bool(self.api_keys.get('OTX', '').strip())
        validation['AbuseIPDB'] = bool(self.api_keys.get('AbuseIPDB', '').strip())
        validation['MalwareBazaar'] = True  # No key required
        
        return validation
    
    def get_api_status(self) -> Dict[str, Any]:
        """Get API connection status and configuration"""
        status = {
            'configured_apis': self.validate_api_keys(),
            'total_apis': 3,
            'configured_count': sum(self.validate_api_keys().values())
        }
        
        return status
