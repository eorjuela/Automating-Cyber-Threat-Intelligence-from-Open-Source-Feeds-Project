"""
Scheduler Module
Handles task scheduling and collection orchestration
"""

import schedule
import time
import logging
from typing import Dict, Any

class CTIScheduler:
    """Handles scheduling and orchestration of collection tasks"""
    
    def __init__(self, db, api_ingestion):
        self.db = db
        self.api_ingestion = api_ingestion
        self.logger = logging.getLogger(__name__)
        
        # Schedule configuration
        self.collection_interval = 6  # hours
        self.is_running = False
    
    def run_collection(self) -> Dict[str, Any]:
        """Run a complete collection job with full orchestration"""
        self.logger.info("Starting CTI collection job...")
        
        # Collect from all sources with individual error handling
        all_iocs = []
        collection_errors = []
        
        # Collect from OTX
        try:
            from config import Config
            config = Config()
            
            otx_total = 0
            for domain in config.THREAT_DOMAINS:
                try:
                    otx_iocs = self.api_ingestion.fetch_otx(domain)
                    all_iocs.extend(otx_iocs)
                    otx_total += len(otx_iocs)
                    self.logger.info(f"OTX: Collected {len(otx_iocs)} URLs from {domain}")
                except Exception as e:
                    error_msg = f"OTX collection failed for {domain}: {e}"
                    collection_errors.append(error_msg)
                    self.logger.error(error_msg)
            
            self.logger.info(f"OTX: Total collected {otx_total} IoCs from {len(config.THREAT_DOMAINS)} domains")
        except Exception as e:
            error_msg = f"OTX collection failed: {e}"
            collection_errors.append(error_msg)
            self.logger.error(error_msg)
        
        # Collect from AbuseIPDB
        try:
            from config import Config
            config = Config()
            
            abuse_iocs = self.api_ingestion.fetch_abuseipdb(limit=config.ABUSEIPDB_LIMIT)
            all_iocs.extend(abuse_iocs)
            self.logger.info(f"AbuseIPDB: Collected {len(abuse_iocs)} IPs from blacklist")
        except Exception as e:
            error_msg = f"AbuseIPDB collection failed: {e}"
            collection_errors.append(error_msg)
            self.logger.error(error_msg)
        
        # Collect from MalwareBazaar - Using export feed (no API blocks)
        try:
            from config import Config
            config = Config()
            
            mb_iocs = self.api_ingestion.fetch_malwarebazaar(limit=config.MALWAREBazaar_LIMIT)
            all_iocs.extend(mb_iocs)
            self.logger.info(f"MalwareBazaar: Collected {len(mb_iocs)} hashes (limit: {config.MALWAREBazaar_LIMIT})")
        except Exception as e:
            error_msg = f"MalwareBazaar collection failed: {e}"
            collection_errors.append(error_msg)
            self.logger.error(error_msg)
        
        # Process collected IoCs
        if all_iocs:
            stats = self.db.insert_or_update_iocs(all_iocs)
            error_summary = "; ".join(collection_errors) if collection_errors else None
            self.db.log_collection("CTI_Collector", stats, error_summary)
            
            self.logger.info(f"Collection completed: {stats}")
            print(f"Collection Stats: {stats}")
            
            return {
                'status': 'success',
                'stats': stats,
                'errors': collection_errors,
                'total_collected': len(all_iocs)
            }
        else:
            self.logger.warning("No IoCs collected in this run")
            print("No IoCs collected in this run")
            
            return {
                'status': 'no_data',
                'stats': {'processed': 0, 'new': 0, 'updated': 0, 'errors': 0},
                'errors': collection_errors,
                'total_collected': 0
            }
    
    def start_scheduling(self):
        """Start the scheduled collection tasks with daily schedule"""
        self.logger.info("Scheduling daily collection at 09:00")
        
        # Schedule daily collection
        schedule.every().day.at("09:00").do(self.run_collection)
        
        # Run initial collection
        print("Running initial collection...")
        result = self.run_collection()
        
        # Show statistics after initial collection
        print("\nCollection Statistics:")
        stats = self.db.get_collection_stats()
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
        # Start scheduling loop
        self.is_running = True
        print("\nScheduled daily collection at 09:00")
        print("Press Ctrl+C to stop...")
        
        try:
            while self.is_running:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            print("\nShutting down collector...")
            self.logger.info("Scheduler stopped by user")
            self.stop_scheduling()
    
    def stop_scheduling(self):
        """Stop the scheduler"""
        self.is_running = False
        self.logger.info("Scheduler stopped")
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get comprehensive system statistics"""
        db_stats = self.db.get_collection_stats()
        
        return {
            'database': db_stats,
            'scheduler': {
                'is_running': self.is_running,
                'collection_interval': self.collection_interval,
                'next_run': str(schedule.next_run()) if schedule.jobs else None
            }
        }
