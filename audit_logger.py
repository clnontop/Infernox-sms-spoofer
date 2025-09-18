"""
Comprehensive Audit and Logging System
Tracks all SMS operations, security events, and compliance data
"""

import logging
import json
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
import threading
from contextlib import contextmanager
import os
import gzip
import shutil

@dataclass
class SMSAuditRecord:
    """SMS audit record structure"""
    timestamp: datetime
    request_id: str
    user_id: str
    user_ip: str
    recipient_number: str
    sender_id: str
    message_content: str
    message_hash: str
    provider: str
    success: bool
    message_id: Optional[str]
    error_message: Optional[str]
    purpose: str
    authorization_level: str
    compliance_flags: List[str]
    cost: Optional[float]
    session_id: str
    user_agent: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data

@dataclass
class SecurityEvent:
    """Security event record"""
    timestamp: datetime
    event_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    user_id: str
    user_ip: str
    description: str
    details: Dict
    action_taken: str
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data

class AuditLogger:
    """Comprehensive audit logging system"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.db_path = config.get('audit_db_path', 'audit.db')
        self.log_file = config.get('audit_log_file', 'logs/audit.log')
        self.security_log_file = config.get('security_log_file', 'logs/security.log')
        self.retention_days = config.get('retention_days', 90)
        self.encryption_key = config.get('encryption_key', '').encode()
        
        # Create directories
        Path(self.log_file).parent.mkdir(parents=True, exist_ok=True)
        Path(self.security_log_file).parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        # Setup file loggers
        self._setup_loggers()
        
        # Thread lock for database operations
        self.db_lock = threading.Lock()
    
    def _init_database(self):
        """Initialize SQLite database for audit records"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS sms_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    request_id TEXT UNIQUE NOT NULL,
                    user_id TEXT NOT NULL,
                    user_ip TEXT NOT NULL,
                    recipient_number TEXT NOT NULL,
                    sender_id TEXT,
                    message_content_hash TEXT NOT NULL,
                    message_content_encrypted TEXT,
                    provider TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    message_id TEXT,
                    error_message TEXT,
                    purpose TEXT NOT NULL,
                    authorization_level TEXT NOT NULL,
                    compliance_flags TEXT,
                    cost REAL,
                    session_id TEXT,
                    user_agent TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    user_id TEXT,
                    user_ip TEXT,
                    description TEXT NOT NULL,
                    details TEXT,
                    action_taken TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS rate_limiting (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    user_ip TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for performance
            conn.execute('CREATE INDEX IF NOT EXISTS idx_sms_audit_timestamp ON sms_audit(timestamp)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_sms_audit_user_id ON sms_audit(user_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_rate_limiting_user_id ON rate_limiting(user_id)')
            
            conn.commit()
    
    def _setup_loggers(self):
        """Setup file loggers for audit and security events"""
        # Audit logger
        self.audit_logger = logging.getLogger('audit')
        self.audit_logger.setLevel(logging.INFO)
        
        audit_handler = logging.FileHandler(self.log_file)
        audit_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        audit_handler.setFormatter(audit_formatter)
        self.audit_logger.addHandler(audit_handler)
        
        # Security logger
        self.security_logger = logging.getLogger('security')
        self.security_logger.setLevel(logging.WARNING)
        
        security_handler = logging.FileHandler(self.security_log_file)
        security_formatter = logging.Formatter(
            '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
        )
        security_handler.setFormatter(security_formatter)
        self.security_logger.addHandler(security_handler)
    
    def _encrypt_message(self, message: str) -> str:
        """Encrypt message content for storage"""
        if not self.encryption_key:
            return message  # Store in plain text if no encryption key
        
        try:
            from cryptography.fernet import Fernet
            f = Fernet(self.encryption_key)
            return f.encrypt(message.encode()).decode()
        except Exception:
            return message  # Fallback to plain text
    
    def _decrypt_message(self, encrypted_message: str) -> str:
        """Decrypt message content"""
        if not self.encryption_key:
            return encrypted_message
        
        try:
            from cryptography.fernet import Fernet
            f = Fernet(self.encryption_key)
            return f.decrypt(encrypted_message.encode()).decode()
        except Exception:
            return encrypted_message
    
    def _hash_message(self, message: str) -> str:
        """Create hash of message content"""
        return hashlib.sha256(message.encode()).hexdigest()
    
    @contextmanager
    def _get_db_connection(self):
        """Get database connection with proper locking"""
        with self.db_lock:
            conn = sqlite3.connect(self.db_path)
            try:
                yield conn
            finally:
                conn.close()
    
    def log_sms_attempt(self, record: SMSAuditRecord):
        """Log SMS sending attempt"""
        try:
            # Hash and encrypt message content
            message_hash = self._hash_message(record.message_content)
            encrypted_content = self._encrypt_message(record.message_content)
            
            # Store in database
            with self._get_db_connection() as conn:
                conn.execute('''
                    INSERT INTO sms_audit (
                        timestamp, request_id, user_id, user_ip, recipient_number,
                        sender_id, message_content_hash, message_content_encrypted,
                        provider, success, message_id, error_message, purpose,
                        authorization_level, compliance_flags, cost, session_id, user_agent
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    record.timestamp.isoformat(),
                    record.request_id,
                    record.user_id,
                    record.user_ip,
                    record.recipient_number,
                    record.sender_id,
                    message_hash,
                    encrypted_content,
                    record.provider,
                    record.success,
                    record.message_id,
                    record.error_message,
                    record.purpose,
                    record.authorization_level,
                    json.dumps(record.compliance_flags),
                    record.cost,
                    record.session_id,
                    record.user_agent
                ))
                conn.commit()
            
            # Log to file
            log_data = record.to_dict()
            # Remove sensitive content from file log
            log_data['message_content'] = f"[HASH:{message_hash[:16]}...]"
            
            self.audit_logger.info(json.dumps(log_data))
            
        except Exception as e:
            self.security_logger.error(f"Failed to log SMS audit record: {str(e)}")
    
    def log_security_event(self, event: SecurityEvent):
        """Log security event"""
        try:
            # Store in database
            with self._get_db_connection() as conn:
                conn.execute('''
                    INSERT INTO security_events (
                        timestamp, event_type, severity, user_id, user_ip,
                        description, details, action_taken
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event.timestamp.isoformat(),
                    event.event_type,
                    event.severity,
                    event.user_id,
                    event.user_ip,
                    event.description,
                    json.dumps(event.details),
                    event.action_taken
                ))
                conn.commit()
            
            # Log to file based on severity
            log_level = {
                'LOW': logging.INFO,
                'MEDIUM': logging.WARNING,
                'HIGH': logging.ERROR,
                'CRITICAL': logging.CRITICAL
            }.get(event.severity, logging.WARNING)
            
            self.security_logger.log(log_level, json.dumps(event.to_dict()))
            
        except Exception as e:
            logging.error(f"Failed to log security event: {str(e)}")
    
    def log_rate_limit_event(self, user_id: str, user_ip: str, action_type: str):
        """Log rate limiting event"""
        try:
            with self._get_db_connection() as conn:
                conn.execute('''
                    INSERT INTO rate_limiting (user_id, user_ip, timestamp, action_type)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, user_ip, datetime.utcnow().isoformat(), action_type))
                conn.commit()
        except Exception as e:
            logging.error(f"Failed to log rate limit event: {str(e)}")
    
    def get_user_sms_count(self, user_id: str, hours: int = 24) -> int:
        """Get SMS count for user in specified time period"""
        try:
            cutoff_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
            
            with self._get_db_connection() as conn:
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM sms_audit 
                    WHERE user_id = ? AND timestamp >= ?
                ''', (user_id, cutoff_time))
                return cursor.fetchone()[0]
        except Exception:
            return 0
    
    def get_ip_sms_count(self, user_ip: str, hours: int = 24) -> int:
        """Get SMS count for IP in specified time period"""
        try:
            cutoff_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
            
            with self._get_db_connection() as conn:
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM sms_audit 
                    WHERE user_ip = ? AND timestamp >= ?
                ''', (user_ip, cutoff_time))
                return cursor.fetchone()[0]
        except Exception:
            return 0
    
    def get_audit_records(self, user_id: str = None, start_date: datetime = None, 
                         end_date: datetime = None, limit: int = 100) -> List[Dict]:
        """Retrieve audit records with filters"""
        try:
            query = "SELECT * FROM sms_audit WHERE 1=1"
            params = []
            
            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)
            
            if start_date:
                query += " AND timestamp >= ?"
                params.append(start_date.isoformat())
            
            if end_date:
                query += " AND timestamp <= ?"
                params.append(end_date.isoformat())
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            with self._get_db_connection() as conn:
                cursor = conn.execute(query, params)
                columns = [description[0] for description in cursor.description]
                records = []
                
                for row in cursor.fetchall():
                    record = dict(zip(columns, row))
                    # Decrypt message content if needed
                    if record.get('message_content_encrypted'):
                        record['message_content'] = self._decrypt_message(
                            record['message_content_encrypted']
                        )
                    records.append(record)
                
                return records
        except Exception as e:
            logging.error(f"Failed to retrieve audit records: {str(e)}")
            return []
    
    def get_security_events(self, severity: str = None, hours: int = 24) -> List[Dict]:
        """Get recent security events"""
        try:
            cutoff_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
            query = "SELECT * FROM security_events WHERE timestamp >= ?"
            params = [cutoff_time]
            
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            
            query += " ORDER BY timestamp DESC"
            
            with self._get_db_connection() as conn:
                cursor = conn.execute(query, params)
                columns = [description[0] for description in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except Exception as e:
            logging.error(f"Failed to retrieve security events: {str(e)}")
            return []
    
    def cleanup_old_records(self):
        """Clean up old audit records based on retention policy"""
        try:
            cutoff_date = (datetime.utcnow() - timedelta(days=self.retention_days)).isoformat()
            
            with self._get_db_connection() as conn:
                # Archive old records before deletion (optional)
                self._archive_old_records(conn, cutoff_date)
                
                # Delete old records
                cursor = conn.execute('DELETE FROM sms_audit WHERE timestamp < ?', (cutoff_date,))
                deleted_sms = cursor.rowcount
                
                cursor = conn.execute('DELETE FROM security_events WHERE timestamp < ?', (cutoff_date,))
                deleted_security = cursor.rowcount
                
                cursor = conn.execute('DELETE FROM rate_limiting WHERE timestamp < ?', (cutoff_date,))
                deleted_rate = cursor.rowcount
                
                conn.commit()
                
                logging.info(f"Cleaned up old records: {deleted_sms} SMS, {deleted_security} security, {deleted_rate} rate limiting")
                
        except Exception as e:
            logging.error(f"Failed to cleanup old records: {str(e)}")
    
    def _archive_old_records(self, conn, cutoff_date: str):
        """Archive old records to compressed files"""
        try:
            archive_dir = Path("archives")
            archive_dir.mkdir(exist_ok=True)
            
            # Archive SMS records
            cursor = conn.execute('SELECT * FROM sms_audit WHERE timestamp < ?', (cutoff_date,))
            sms_records = cursor.fetchall()
            
            if sms_records:
                archive_file = archive_dir / f"sms_audit_{datetime.now().strftime('%Y%m%d')}.json.gz"
                with gzip.open(archive_file, 'wt') as f:
                    json.dump([dict(zip([col[0] for col in cursor.description], row)) 
                              for row in sms_records], f)
            
            # Archive security events
            cursor = conn.execute('SELECT * FROM security_events WHERE timestamp < ?', (cutoff_date,))
            security_records = cursor.fetchall()
            
            if security_records:
                archive_file = archive_dir / f"security_events_{datetime.now().strftime('%Y%m%d')}.json.gz"
                with gzip.open(archive_file, 'wt') as f:
                    json.dump([dict(zip([col[0] for col in cursor.description], row)) 
                              for row in security_records], f)
                    
        except Exception as e:
            logging.warning(f"Failed to archive old records: {str(e)}")
    
    def generate_compliance_report(self, start_date: datetime, end_date: datetime) -> Dict:
        """Generate compliance report for specified period"""
        try:
            with self._get_db_connection() as conn:
                # SMS statistics
                cursor = conn.execute('''
                    SELECT 
                        COUNT(*) as total_sms,
                        COUNT(CASE WHEN success = 1 THEN 1 END) as successful_sms,
                        COUNT(CASE WHEN success = 0 THEN 1 END) as failed_sms,
                        COUNT(DISTINCT user_id) as unique_users,
                        COUNT(DISTINCT user_ip) as unique_ips,
                        SUM(CASE WHEN cost IS NOT NULL THEN cost ELSE 0 END) as total_cost
                    FROM sms_audit 
                    WHERE timestamp BETWEEN ? AND ?
                ''', (start_date.isoformat(), end_date.isoformat()))
                
                sms_stats = dict(zip([col[0] for col in cursor.description], cursor.fetchone()))
                
                # Purpose breakdown
                cursor = conn.execute('''
                    SELECT purpose, COUNT(*) as count
                    FROM sms_audit 
                    WHERE timestamp BETWEEN ? AND ?
                    GROUP BY purpose
                ''', (start_date.isoformat(), end_date.isoformat()))
                
                purpose_breakdown = dict(cursor.fetchall())
                
                # Security events
                cursor = conn.execute('''
                    SELECT severity, COUNT(*) as count
                    FROM security_events 
                    WHERE timestamp BETWEEN ? AND ?
                    GROUP BY severity
                ''', (start_date.isoformat(), end_date.isoformat()))
                
                security_stats = dict(cursor.fetchall())
                
                return {
                    'report_period': {
                        'start': start_date.isoformat(),
                        'end': end_date.isoformat()
                    },
                    'sms_statistics': sms_stats,
                    'purpose_breakdown': purpose_breakdown,
                    'security_statistics': security_stats,
                    'generated_at': datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logging.error(f"Failed to generate compliance report: {str(e)}")
            return {}

class ComplianceChecker:
    """Compliance and policy enforcement"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.prohibited_patterns = config.get('prohibited_patterns', [])
        self.required_purposes = config.get('allowed_purposes', [])
    
    def check_message_compliance(self, message: str, purpose: str) -> List[str]:
        """Check message for compliance violations"""
        violations = []
        
        # Check for prohibited content
        message_lower = message.lower()
        for pattern in self.prohibited_patterns:
            if pattern.lower() in message_lower:
                violations.append(f"Prohibited content detected: {pattern}")
        
        # Check purpose validity
        if purpose not in self.required_purposes:
            violations.append(f"Invalid purpose: {purpose}")
        
        # Check for suspicious patterns
        if self._contains_suspicious_patterns(message):
            violations.append("Suspicious content patterns detected")
        
        return violations
    
    def _contains_suspicious_patterns(self, message: str) -> bool:
        """Check for suspicious patterns that might indicate misuse"""
        suspicious_keywords = [
            'urgent', 'winner', 'congratulations', 'click here',
            'verify account', 'suspended', 'limited time',
            'act now', 'free money', 'guaranteed'
        ]
        
        message_lower = message.lower()
        suspicious_count = sum(1 for keyword in suspicious_keywords 
                             if keyword in message_lower)
        
        return suspicious_count >= 2  # Flag if multiple suspicious keywords
