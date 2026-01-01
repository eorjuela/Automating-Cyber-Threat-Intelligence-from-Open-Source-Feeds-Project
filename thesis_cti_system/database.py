"""
Database Module
Handles all database operations and schema management
"""

import sqlite3
import json
import logging
from typing import List, Dict, Any
from datetime import datetime

class CTIDatabase:
    """Database manager for CTI collection system"""
    
    def __init__(self, db_path: str = "cti_thesis.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.logger = logging.getLogger(__name__)
        self.setup_schema()
        self.logger.info(f"Database initialized: {db_path}")
    
    def setup_schema(self):
        """Setup database schema"""
        cursor = self.conn.cursor()
        
        # Main IoCs table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            indicator TEXT NOT NULL,
            type TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            seen_count INTEGER NOT NULL DEFAULT 1,
            confidence TEXT DEFAULT 'medium',
            threat_level TEXT DEFAULT 'medium',
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (indicator, type)
        )
        """)
        
        # Collection logs
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS collection_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            collection_time TEXT NOT NULL,
            iocs_processed INTEGER DEFAULT 0,
            iocs_new INTEGER DEFAULT 0,
            iocs_updated INTEGER DEFAULT 0,
            errors TEXT,
            status TEXT DEFAULT 'success',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        self.conn.commit()
    
    def insert_or_update_iocs(self, iocs: List[Dict[str, Any]]) -> Dict[str, int]:
        """Insert or update IoCs with deduplication"""
        cursor = self.conn.cursor()
        stats = {'processed': 0, 'new': 0, 'updated': 0, 'errors': 0}
        
        for ioc in iocs:
            try:
                stats['processed'] += 1
                
                # Check if IoC exists
                cursor.execute("""
                SELECT first_seen, last_seen, seen_count FROM iocs 
                WHERE indicator=? AND type=?
                """, (ioc['indicator'], ioc['type']))
                
                row = cursor.fetchone()
                
                if row is None:
                    # New IoC
                    cursor.execute("""
                    INSERT INTO iocs (indicator, type, source, first_seen, last_seen, 
                                    seen_count, confidence, threat_level, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        ioc['indicator'], ioc['type'], ioc['source'], 
                        ioc['date_collected'], ioc['date_collected'], 1,
                        ioc.get('confidence', 'medium'), ioc.get('threat_level', 'medium'),
                        json.dumps(ioc.get('metadata', {}))
                    ))
                    stats['new'] += 1
                    self.logger.info(f"Inserted new IoC: {ioc['indicator']} ({ioc['type']})")
                    
                else:
                    # Update existing IoC
                    first_seen, last_seen, seen_count = row
                    new_last = max(last_seen, ioc['date_collected'])
                    new_count = seen_count + 1
                    
                    cursor.execute("""
                    UPDATE iocs SET last_seen=?, seen_count=?, source=?, 
                                  confidence=?, threat_level=?, metadata=?
                    WHERE indicator=? AND type=?
                    """, (
                        new_last, new_count, ioc['source'], 
                        ioc.get('confidence', 'medium'), ioc.get('threat_level', 'medium'),
                        json.dumps(ioc.get('metadata', {})),
                        ioc['indicator'], ioc['type']
                    ))
                    stats['updated'] += 1
                    self.logger.info(f"Updated IoC: {ioc['indicator']} (count: {new_count})")
                    
            except Exception as e:
                stats['errors'] += 1
                self.logger.error(f"Error processing IoC {ioc['indicator']}: {e}")
        
        self.conn.commit()
        return stats
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get comprehensive collection statistics for thesis evaluation"""
        cursor = self.conn.cursor()
        stats = {}
        
        # Total IoCs
        cursor.execute("SELECT COUNT(*) FROM iocs")
        stats['total_iocs'] = cursor.fetchone()[0]
        
        # IoCs by type
        cursor.execute("SELECT type, COUNT(*) FROM iocs GROUP BY type ORDER BY COUNT(*) DESC")
        stats['by_type'] = dict(cursor.fetchall())
        
        # IoCs by source
        cursor.execute("SELECT source, COUNT(*) FROM iocs GROUP BY source ORDER BY COUNT(*) DESC")
        stats['by_source'] = dict(cursor.fetchall())
        
        # Recent activity (last 7 days)
        cursor.execute("""
        SELECT DATE(first_seen), COUNT(*) FROM iocs 
        WHERE first_seen >= date('now', '-7 days') 
        GROUP BY DATE(first_seen)
        """)
        stats['recent_activity'] = dict(cursor.fetchall())
        
        # Collection logs count
        cursor.execute("SELECT COUNT(*) FROM collection_logs")
        stats['collection_runs'] = cursor.fetchone()[0]
        
        # Deduplication statistics
        cursor.execute("SELECT AVG(seen_count), MAX(seen_count) FROM iocs")
        avg_seen, max_seen = cursor.fetchone()
        stats['deduplication'] = {
            'avg_seen_count': avg_seen or 0,
            'max_seen_count': max_seen or 0
        }
        
        # Success/failure rates
        cursor.execute("SELECT status, COUNT(*) FROM collection_logs GROUP BY status")
        status_counts = dict(cursor.fetchall())
        stats['collection_success_rate'] = {
            'success': status_counts.get('success', 0),
            'error': status_counts.get('error', 0),
            'total': sum(status_counts.values())
        }
        
        return stats
    
    def log_collection(self, source: str, stats: Dict[str, int], errors: str = None):
        """Log collection activity for thesis evaluation"""
        cursor = self.conn.cursor()
        cursor.execute("""
        INSERT INTO collection_logs (source, collection_time, iocs_processed, iocs_new, iocs_updated, errors, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            source, datetime.now().isoformat(), stats['processed'],
            stats['new'], stats['updated'], errors,
            'success' if not errors else 'error'
        ))
        self.conn.commit()
        self.logger.info(f"Logged collection: {source} - {stats}")
    
    def close(self):
        """Close database connection"""
        self.conn.close()
