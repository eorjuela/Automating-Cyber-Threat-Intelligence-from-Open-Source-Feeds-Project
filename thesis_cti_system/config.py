"""
Configuration Module
Centralized configuration management
"""

import os
from pathlib import Path

class Config:
    """Configuration management for CTI system"""
    
    def __init__(self):
        # Database configuration
        self.DB_PATH = "cti_thesis.db"
        
        # API Keys
        self.API_KEYS = {
            'OTX': os.getenv('OTX_API_KEY', 'b6c7509b96609abdb328e72c04530ed9289d99c12a1f1f0a81f71cb2d72956eb'),
            'AbuseIPDB': os.getenv('ABUSEIPDB_API_KEY', '9e92b59ddbacd503f78009889be2d10c99e44d73047b4d862557e9581ffcaa0e28cb1377b4a6299e'),
        }
        
        # Collection configuration
        self.COLLECTION_INTERVAL_HOURS = 6
        self.DEFAULT_DOMAIN = "example.com"
        self.DEFAULT_IP = "8.8.8.8"
        self.MALWAREBazaar_LIMIT = 10000  
        self.ABUSEIPDB_LIMIT = 10000
        
        self.THREAT_DOMAINS = [
            # Security/Threat Intelligence Sources
            "urlhaus.abuse.ch",
            "phishtank.com",
            "malware-traffic-analysis.net",
            "otx.alienvault.com",
            "virustotal.com",
            "threatcrowd.org",
            "malwaredomainlist.com",
            "cybercrime-tracker.net",
            "ransomwaretracker.abuse.ch",
            "feodotracker.abuse.ch",
            "sslbl.abuse.ch",
            "zeustracker.abuse.ch",
            "example.com",
            # Tech Companies (High-value targets)
            "microsoft.com",
            "apple.com",
            "google.com",
            "amazon.com",
            "facebook.com",
            "meta.com",
            "twitter.com",
            "x.com",
            "github.com",
            "gitlab.com",
            "bitbucket.org",
            "dropbox.com",
            "onedrive.com",
            "cloudflare.com",
            "adobe.com",
            "oracle.com",
            "salesforce.com",
            "vmware.com",
            "cisco.com",
            "ibm.com",
            "intel.com",
            "nvidia.com",
            # Social Media Platforms
            "instagram.com",
            "tiktok.com",
            "linkedin.com",
            "reddit.com",
            "snapchat.com",
            "pinterest.com",
            "discord.com",
            "telegram.org",
            "signal.org",
            "whatsapp.com",
            # Financial Services (Commonly phished)
            "paypal.com",
            "visa.com",
            "mastercard.com",
            "americanexpress.com",
            "chase.com",
            "bankofamerica.com",
            "wellsfargo.com",
            "citibank.com",
            "jpmorgan.com",
            "goldmansachs.com",
            "morganstanley.com",
            "schwab.com",
            "fidelity.com",
            "etrade.com",
            "coinbase.com",
            "binance.com",
            # E-commerce & Retail
            "ebay.com",
            "etsy.com",
            "walmart.com",
            "target.com",
            "bestbuy.com",
            "costco.com",
            "alibaba.com",
            "aliexpress.com",
            # Email & Communication
            "gmail.com",
            "outlook.com",
            "yahoo.com",
            "protonmail.com",
            "aol.com",
            "hotmail.com",
            "zoom.us",
            "teams.microsoft.com",
            "slack.com",
            "skype.com",
            # Streaming & Entertainment
            "netflix.com",
            "spotify.com",
            "youtube.com",
            "hulu.com",
            "disney.com",
            "hbo.com",
            "paramount.com",
            # News & Media
            "cnn.com",
            "bbc.com",
            "reuters.com",
            "bloomberg.com",
            "wsj.com",
            "nytimes.com",
            "washingtonpost.com",
            # Government & Official
            "irs.gov",
            "usps.com",
            "fedex.com",
            "ups.com",
            "dhl.com",
            # Gaming Platforms
            "steam.com",
            "epicgames.com",
            "xbox.com",
            "playstation.com",
            "nintendo.com",
            "blizzard.com",
            "riotgames.com",
            # Cloud & Infrastructure
            "aws.amazon.com",
            "azure.microsoft.com",
            "gcp.google.com",
            "digitalocean.com",
            "heroku.com",
            "vercel.com",
            "netlify.com"
        ]
        
        self.MALICIOUS_IPS = [
            "8.8.8.8",                    
            "1.1.1.1",                    
            "208.67.222.222",             
            "10.0.0.1",                  
            "192.168.1.1"                 
        ]
        
        # Logging configuration
        self.LOG_LEVEL = "INFO"
        self.LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        self.LOG_FILE = "logs/cti_system.log"
        
        # Create necessary directories
        self._create_directories()
    
    def _create_directories(self):
        """Create necessary directories"""
        Path("logs").mkdir(exist_ok=True)
        Path("data").mkdir(exist_ok=True)
    
    def validate_config(self) -> bool:
        """Validate configuration"""
        # Check if API keys are configured
        if not self.API_KEYS['OTX']:
            print("Warning: OTX API key not configured")
        if not self.API_KEYS['AbuseIPDB']:
            print("Warning: AbuseIPDB API key not configured")
        
        return True
    
    def get_api_key(self, service: str) -> str:
        """Get API key for service"""
        return self.API_KEYS.get(service, '')
    
    def update_api_key(self, service: str, key: str):
        """Update API key for service"""
        self.API_KEYS[service] = key

