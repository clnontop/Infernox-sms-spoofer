"""
Security and Authorization Manager
Handles authentication, authorization, rate limiting, and security enforcement
"""

import jwt
import bcrypt
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from functools import wraps
import ipaddress
import re
import logging
from collections import defaultdict, deque
import threading

logger = logging.getLogger(__name__)

@dataclass
class User:
    """User account information"""
    user_id: str
    username: str
    email: str
    password_hash: str
    role: str
    permissions: List[str]
    created_at: datetime
    last_login: Optional[datetime]
    is_active: bool
    failed_login_attempts: int
    locked_until: Optional[datetime]
    two_factor_enabled: bool
    two_factor_secret: Optional[str]

@dataclass
class Session:
    """User session information"""
    session_id: str
    user_id: str
    ip_address: str
    user_agent: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    is_active: bool

class RateLimiter:
    """Advanced rate limiting with multiple strategies"""
    
    def __init__(self):
        self.requests = defaultdict(lambda: deque())
        self.lock = threading.Lock()
    
    def is_allowed(self, key: str, limit: int, window_seconds: int) -> Tuple[bool, int]:
        """Check if request is allowed under rate limit"""
        with self.lock:
            now = time.time()
            window_start = now - window_seconds
            
            # Clean old requests
            while self.requests[key] and self.requests[key][0] < window_start:
                self.requests[key].popleft()
            
            current_count = len(self.requests[key])
            
            if current_count >= limit:
                return False, current_count
            
            # Add current request
            self.requests[key].append(now)
            return True, current_count + 1
    
    def get_reset_time(self, key: str, window_seconds: int) -> int:
        """Get time until rate limit resets"""
        with self.lock:
            if not self.requests[key]:
                return 0
            
            oldest_request = self.requests[key][0]
            reset_time = oldest_request + window_seconds
            return max(0, int(reset_time - time.time()))

class SecurityManager:
    """Comprehensive security management system"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.jwt_secret = config['jwt_secret_key']
        self.rate_limiter = RateLimiter()
        self.users = {}  # In production, use proper database
        self.sessions = {}
        self.blocked_ips = set()
        self.suspicious_activities = defaultdict(list)
        
        # Security settings
        self.max_login_attempts = config.get('max_login_attempts', 5)
        self.lockout_duration = config.get('lockout_duration_minutes', 30)
        self.session_timeout = config.get('session_timeout_hours', 24)
        self.password_min_length = config.get('password_min_length', 12)
        
        # Rate limiting settings
        self.rate_limits = {
            'sms_per_minute': config.get('sms_per_minute', 5),
            'sms_per_hour': config.get('sms_per_hour', 50),
            'sms_per_day': config.get('sms_per_day', 200),
            'login_per_minute': config.get('login_per_minute', 5),
            'api_per_minute': config.get('api_per_minute', 60)
        }
        
        # IP whitelist/blacklist
        self.ip_whitelist = set(config.get('ip_whitelist', []))
        self.ip_blacklist = set(config.get('ip_blacklist', []))
        
        # Initialize default admin user
        self._create_default_admin()
    
    def _create_default_admin(self):
        """Create default admin user if none exists"""
        admin_password = self.config.get('default_admin_password', 'admin123!@#')
        
        if not any(user.role == 'admin' for user in self.users.values()):
            admin_user = User(
                user_id='admin',
                username='admin',
                email='admin@localhost',
                password_hash=self._hash_password(admin_password),
                role='admin',
                permissions=['sms_send', 'sms_spoof', 'user_manage', 'audit_view', 'system_config'],
                created_at=datetime.utcnow(),
                last_login=None,
                is_active=True,
                failed_login_attempts=0,
                locked_until=None,
                two_factor_enabled=False,
                two_factor_secret=None
            )
            self.users['admin'] = admin_user
            logger.info("Created default admin user")
    
    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    
    def _generate_session_id(self) -> str:
        """Generate secure session ID"""
        return secrets.token_urlsafe(32)
    
    def _generate_jwt_token(self, user_id: str, session_id: str) -> str:
        """Generate JWT token for user session"""
        payload = {
            'user_id': user_id,
            'session_id': session_id,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=self.session_timeout)
        }
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
    
    def validate_password_strength(self, password: str) -> List[str]:
        """Validate password strength"""
        issues = []
        
        if len(password) < self.password_min_length:
            issues.append(f"Password must be at least {self.password_min_length} characters")
        
        if not re.search(r'[A-Z]', password):
            issues.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', password):
            issues.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', password):
            issues.append("Password must contain at least one digit")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            issues.append("Password must contain at least one special character")
        
        # Check for common patterns
        common_patterns = ['123456', 'password', 'qwerty', 'admin']
        if any(pattern in password.lower() for pattern in common_patterns):
            issues.append("Password contains common patterns")
        
        return issues
    
    def create_user(self, username: str, email: str, password: str, role: str = 'user') -> Dict:
        """Create new user account"""
        try:
            # Validate inputs
            if username in [user.username for user in self.users.values()]:
                return {'success': False, 'error': 'Username already exists'}
            
            if email in [user.email for user in self.users.values()]:
                return {'success': False, 'error': 'Email already exists'}
            
            # Validate password
            password_issues = self.validate_password_strength(password)
            if password_issues:
                return {'success': False, 'error': 'Password validation failed', 'details': password_issues}
            
            # Define role permissions
            role_permissions = {
                'admin': ['sms_send', 'sms_spoof', 'user_manage', 'audit_view', 'system_config'],
                'operator': ['sms_send', 'sms_spoof', 'audit_view'],
                'user': ['sms_send'],
                'readonly': ['audit_view']
            }
            
            user_id = secrets.token_urlsafe(16)
            user = User(
                user_id=user_id,
                username=username,
                email=email,
                password_hash=self._hash_password(password),
                role=role,
                permissions=role_permissions.get(role, ['sms_send']),
                created_at=datetime.utcnow(),
                last_login=None,
                is_active=True,
                failed_login_attempts=0,
                locked_until=None,
                two_factor_enabled=False,
                two_factor_secret=None
            )
            
            self.users[user_id] = user
            logger.info(f"Created user: {username} with role: {role}")
            
            return {'success': True, 'user_id': user_id}
            
        except Exception as e:
            logger.error(f"Failed to create user: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def authenticate_user(self, username: str, password: str, ip_address: str, 
                         user_agent: str) -> Dict:
        """Authenticate user and create session"""
        try:
            # Check rate limiting for login attempts
            rate_key = f"login:{ip_address}"
            allowed, count = self.rate_limiter.is_allowed(
                rate_key, self.rate_limits['login_per_minute'], 60
            )
            
            if not allowed:
                self._log_security_event('RATE_LIMIT_EXCEEDED', 'MEDIUM', None, ip_address,
                                       'Login rate limit exceeded')
                return {'success': False, 'error': 'Too many login attempts'}
            
            # Find user
            user = None
            for u in self.users.values():
                if u.username == username:
                    user = u
                    break
            
            if not user:
                return {'success': False, 'error': 'Invalid credentials'}
            
            # Check if account is locked
            if user.locked_until and datetime.utcnow() < user.locked_until:
                return {'success': False, 'error': 'Account temporarily locked'}
            
            # Check if account is active
            if not user.is_active:
                return {'success': False, 'error': 'Account disabled'}
            
            # Verify password
            if not self._verify_password(password, user.password_hash):
                # Increment failed attempts
                user.failed_login_attempts += 1
                
                if user.failed_login_attempts >= self.max_login_attempts:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=self.lockout_duration)
                    self._log_security_event('ACCOUNT_LOCKED', 'HIGH', user.user_id, ip_address,
                                           f'Account locked after {self.max_login_attempts} failed attempts')
                
                self._log_security_event('LOGIN_FAILED', 'MEDIUM', user.user_id, ip_address,
                                       'Failed login attempt')
                return {'success': False, 'error': 'Invalid credentials'}
            
            # Reset failed attempts on successful login
            user.failed_login_attempts = 0
            user.locked_until = None
            user.last_login = datetime.utcnow()
            
            # Create session
            session_id = self._generate_session_id()
            session = Session(
                session_id=session_id,
                user_id=user.user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                created_at=datetime.utcnow(),
                last_activity=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(hours=self.session_timeout),
                is_active=True
            )
            
            self.sessions[session_id] = session
            
            # Generate JWT token
            token = self._generate_jwt_token(user.user_id, session_id)
            
            self._log_security_event('LOGIN_SUCCESS', 'LOW', user.user_id, ip_address,
                                   'Successful login')
            
            return {
                'success': True,
                'token': token,
                'user_id': user.user_id,
                'username': user.username,
                'role': user.role,
                'permissions': user.permissions,
                'session_id': session_id
            }
            
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return {'success': False, 'error': 'Authentication error'}
    
    def validate_token(self, token: str, ip_address: str) -> Dict:
        """Validate JWT token and return user info"""
        try:
            # Decode JWT
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            user_id = payload['user_id']
            session_id = payload['session_id']
            
            # Check session
            session = self.sessions.get(session_id)
            if not session or not session.is_active:
                return {'success': False, 'error': 'Invalid session'}
            
            # Check session expiry
            if datetime.utcnow() > session.expires_at:
                session.is_active = False
                return {'success': False, 'error': 'Session expired'}
            
            # Check IP address (optional security measure)
            if self.config.get('enforce_session_ip', False) and session.ip_address != ip_address:
                self._log_security_event('SESSION_IP_MISMATCH', 'HIGH', user_id, ip_address,
                                       f'Session IP mismatch: {session.ip_address} vs {ip_address}')
                session.is_active = False
                return {'success': False, 'error': 'Session security violation'}
            
            # Update session activity
            session.last_activity = datetime.utcnow()
            
            # Get user
            user = self.users.get(user_id)
            if not user or not user.is_active:
                return {'success': False, 'error': 'User not found or inactive'}
            
            return {
                'success': True,
                'user_id': user.user_id,
                'username': user.username,
                'role': user.role,
                'permissions': user.permissions,
                'session_id': session_id
            }
            
        except jwt.ExpiredSignatureError:
            return {'success': False, 'error': 'Token expired'}
        except jwt.InvalidTokenError:
            return {'success': False, 'error': 'Invalid token'}
        except Exception as e:
            logger.error(f"Token validation failed: {str(e)}")
            return {'success': False, 'error': 'Token validation error'}
    
    def check_permission(self, user_id: str, permission: str) -> bool:
        """Check if user has specific permission"""
        user = self.users.get(user_id)
        if not user or not user.is_active:
            return False
        
        return permission in user.permissions or 'admin' in user.role
    
    def check_sms_rate_limit(self, user_id: str, ip_address: str) -> Dict:
        """Check SMS rate limits for user and IP"""
        results = {}
        
        # Check per-minute limit
        user_key = f"sms_user:{user_id}"
        allowed, count = self.rate_limiter.is_allowed(
            user_key, self.rate_limits['sms_per_minute'], 60
        )
        results['minute'] = {'allowed': allowed, 'count': count, 'limit': self.rate_limits['sms_per_minute']}
        
        # Check per-hour limit
        allowed, count = self.rate_limiter.is_allowed(
            user_key, self.rate_limits['sms_per_hour'], 3600
        )
        results['hour'] = {'allowed': allowed, 'count': count, 'limit': self.rate_limits['sms_per_hour']}
        
        # Check per-day limit
        allowed, count = self.rate_limiter.is_allowed(
            user_key, self.rate_limits['sms_per_day'], 86400
        )
        results['day'] = {'allowed': allowed, 'count': count, 'limit': self.rate_limits['sms_per_day']}
        
        # Check IP-based limits
        ip_key = f"sms_ip:{ip_address}"
        allowed, count = self.rate_limiter.is_allowed(
            ip_key, self.rate_limits['sms_per_minute'], 60
        )
        results['ip_minute'] = {'allowed': allowed, 'count': count, 'limit': self.rate_limits['sms_per_minute']}
        
        # Overall allowed status
        results['allowed'] = all(result['allowed'] for result in results.values())
        
        return results
    
    def check_ip_security(self, ip_address: str) -> Dict:
        """Check IP address security status"""
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Check blacklist
            if ip_address in self.ip_blacklist or ip_address in self.blocked_ips:
                return {'allowed': False, 'reason': 'IP blacklisted'}
            
            # Check whitelist (if enabled)
            if self.ip_whitelist and ip_address not in self.ip_whitelist:
                return {'allowed': False, 'reason': 'IP not whitelisted'}
            
            # Check for private/local IPs in production
            if self.config.get('block_private_ips', False) and ip.is_private:
                return {'allowed': False, 'reason': 'Private IP addresses not allowed'}
            
            return {'allowed': True}
            
        except ValueError:
            return {'allowed': False, 'reason': 'Invalid IP address'}
    
    def _log_security_event(self, event_type: str, severity: str, user_id: str, 
                           ip_address: str, description: str, details: Dict = None):
        """Log security event"""
        from audit_logger import SecurityEvent
        
        event = SecurityEvent(
            timestamp=datetime.utcnow(),
            event_type=event_type,
            severity=severity,
            user_id=user_id or 'anonymous',
            user_ip=ip_address,
            description=description,
            details=details or {},
            action_taken='logged'
        )
        
        # In a real implementation, this would use the audit logger
        logger.warning(f"Security Event: {event_type} - {description}")
    
    def logout_user(self, session_id: str):
        """Logout user and invalidate session"""
        session = self.sessions.get(session_id)
        if session:
            session.is_active = False
            logger.info(f"User logged out: {session.user_id}")
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        now = datetime.utcnow()
        expired_sessions = [
            session_id for session_id, session in self.sessions.items()
            if now > session.expires_at
        ]
        
        for session_id in expired_sessions:
            self.sessions[session_id].is_active = False
        
        logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")

def require_auth(permission: str = None):
    """Decorator for requiring authentication and optional permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request, jsonify, g
            
            # Get token from Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Missing or invalid authorization header'}), 401
            
            token = auth_header.split(' ')[1]
            ip_address = request.remote_addr
            
            # Validate token
            security_manager = kwargs.get('security_manager')  # Passed from app context
            if not security_manager:
                return jsonify({'error': 'Security manager not available'}), 500
            
            auth_result = security_manager.validate_token(token, ip_address)
            if not auth_result['success']:
                return jsonify({'error': auth_result['error']}), 401
            
            # Check permission if specified
            if permission and not security_manager.check_permission(auth_result['user_id'], permission):
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            # Add user info to request context
            g.current_user = auth_result
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_rate_limit(limit_type: str = 'api'):
    """Decorator for rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request, jsonify, g
            
            security_manager = kwargs.get('security_manager')
            if not security_manager:
                return jsonify({'error': 'Security manager not available'}), 500
            
            # Check rate limit
            user_id = getattr(g, 'current_user', {}).get('user_id', 'anonymous')
            ip_address = request.remote_addr
            
            if limit_type == 'sms':
                rate_result = security_manager.check_sms_rate_limit(user_id, ip_address)
                if not rate_result['allowed']:
                    return jsonify({
                        'error': 'Rate limit exceeded',
                        'rate_limits': rate_result
                    }), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
