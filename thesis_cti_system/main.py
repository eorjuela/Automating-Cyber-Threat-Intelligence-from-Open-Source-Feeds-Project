"""
CTI Collection System
Main execution module of the CTI collection system
"""

from database import CTIDatabase
from api_ingestion import APIIngestion
from normalization import IoCNormalizer
from scheduler import CTIScheduler
from config import Config
import logging
import os
from pathlib import Path

def setup_logging():
    """Setup comprehensive logging system"""
    # Create logs directory
    Path("logs").mkdir(exist_ok=True)
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("logs/cti_collector.log"),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def main():
    """Main execution function - Complete implementation"""
    logger = setup_logging()
    
    print("CTI Collection System")
    print("=" * 50)
    logger.info("Starting CTI Collection System")
    
    # Initialize configuration
    config = Config()
    config.validate_config()
    
    # Initialize components
    db = CTIDatabase()
    normalizer = IoCNormalizer()
    api_ingestion = APIIngestion(db, normalizer)
    scheduler = CTIScheduler(db, api_ingestion)
    
    # Update API keys from config
    api_ingestion.api_keys['OTX'] = config.get_api_key('OTX')
    api_ingestion.api_keys['AbuseIPDB'] = config.get_api_key('AbuseIPDB')
    
    # Start the complete system
    logger.info("Starting complete CTI collection system...")
    scheduler.start_scheduling()

def run_single_collection():
    """Run a single collection cycle for testing"""
    logger = setup_logging()
    logger.info("Running single collection cycle...")
    
    # Initialize components
    db = CTIDatabase()
    normalizer = IoCNormalizer()
    api_ingestion = APIIngestion(db, normalizer)
    scheduler = CTIScheduler(db, api_ingestion)
    
    # Run collection
    result = scheduler.run_collection()
    
    # Show statistics
    print("\nCollection Statistics:")
    stats = db.get_collection_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    db.close()
    return result

def show_system_stats():
    """Show current system statistics"""
    logger = setup_logging()
    logger.info("Retrieving system statistics...")
    
    # Initialize database
    db = CTIDatabase()
    
    # Get comprehensive statistics
    stats = db.get_collection_stats()
    
    print("CTI Collection System Statistics")
    print("=" * 40)
    print(f"Total IoCs: {stats['total_iocs']}")
    print(f"Collection Runs: {stats['collection_runs']}")
    
    print("\nIoCs by Type:")
    for ioc_type, count in stats['by_type'].items():
        print(f"  {ioc_type}: {count}")
    
    print("\nIoCs by Source:")
    for source, count in stats['by_source'].items():
        print(f"  {source}: {count}")
    
    print("\nRecent Activity (Last 7 Days):")
    for date, count in stats['recent_activity'].items():
        print(f"  {date}: {count}")
    
    print("\nDeduplication Statistics:")
    dedup = stats['deduplication']
    print(f"  Average Seen Count: {dedup['avg_seen_count']:.2f}")
    print(f"  Maximum Seen Count: {dedup['max_seen_count']}")
    
    print("\nCollection Success Rate:")
    success_rate = stats['collection_success_rate']
    if success_rate['total'] > 0:
        success_pct = (success_rate['success'] / success_rate['total']) * 100
        print(f"  Success: {success_rate['success']}/{success_rate['total']} ({success_pct:.1f}%)")
        print(f"  Errors: {success_rate['error']}")
    else:
        print("  No collection runs recorded")
    
    db.close()
    return stats

def run_evaluation():
    """Run comprehensive evaluation comparing automated vs manual collection"""
    logger = setup_logging()
    logger.info("Running evaluation...")
    
    from evaluation import CTIEvaluator
    
    evaluator = CTIEvaluator()
    results = evaluator.run_full_evaluation()
    
    # Print summary
    evaluator.print_evaluation_summary(results)
    
    # Save report
    report_file = evaluator.save_evaluation_report(results)
    print(f"\nFull evaluation report saved to: {report_file}")
    
    return results

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "single":
            # Run single collection
            run_single_collection()
        elif command == "stats":
            # Show statistics
            show_system_stats()
        elif command == "eval" or command == "evaluation":
            # Run evaluation
            run_evaluation()
        elif command == "help":
            print("Usage:")
            print("  python main.py          # Run full system with scheduling")
            print("  python main.py single   # Run single collection cycle")
            print("  python main.py stats    # Show current statistics")
            print("  python main.py eval     # Run evaluation (auto vs manual)")
            print("  python main.py help     # Show this help")
        else:
            print(f"Unknown command: {command}")
            print("Use 'python main.py help' for usage information")
    else:
        # Run full system
        main()
