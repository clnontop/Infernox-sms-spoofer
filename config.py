"""
Configuration management for SMS Spoofing System
Handles environment variables, security settings, and provider configurations
"""

import os
from datetime import timedelta
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """Base configuration class"""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'infernox-dev-secret-key-change-in-production')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'infernox-jwt-secret-key-change-in-production')
    
    # Ensure we have the key in the right format for PyJWT
    jwt_secret_key = JWT_SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///sms_spoofing.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # SMS Provider Configurations
    SMS_PROVIDERS = {
        'twilio': {
            'account_sid': os.environ.get('TWILIO_ACCOUNT_SID'),
            'auth_token': os.environ.get('TWILIO_AUTH_TOKEN'),
            'supports_spoofing': False,  # Twilio doesn't support arbitrary sender IDs
            'api_url': 'https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json'
        },
        'vonage': {
            'api_key': os.environ.get('VONAGE_API_KEY'),
            'api_secret': os.environ.get('VONAGE_API_SECRET'),
            'supports_spoofing': True,
            'api_url': 'https://rest.nexmo.com/sms/json'
        },
        'clicksend': {
            'username': os.environ.get('CLICKSEND_USERNAME'),
            'api_key': os.environ.get('CLICKSEND_API_KEY'),
            'supports_spoofing': True,
            'api_url': 'https://rest.clicksend.com/v3/sms/send'
        },
        'plivo': {
            'auth_id': os.environ.get('PLIVO_AUTH_ID'),
            'auth_token': os.environ.get('PLIVO_AUTH_TOKEN'),
            'supports_spoofing': True,
            'api_url': 'https://api.plivo.com/v1/Account/{auth_id}/Message/'
        },
        'messagebird': {
            'access_key': os.environ.get('MESSAGEBIRD_ACCESS_KEY'),
            'supports_spoofing': True,
            'api_url': 'https://rest.messagebird.com/messages'
        },
        'textbee': {
            'api_key': os.environ.get('TEXTBEE_API_KEY', '3aba67b9-0c34-4e77-b339-78234c6b9273'),
            'device_id': os.environ.get('TEXTBEE_DEVICE_ID', '68ccffff546ea5f868e4eef6'),
            'supports_spoofing': True,
            'api_url': 'https://api.textbee.dev/api/v1'
        },
        'custom_gateway': {
            'api_url': os.environ.get('CUSTOM_SMS_API_URL'),
            'api_key': os.environ.get('CUSTOM_SMS_API_KEY'),
            'supports_spoofing': True
        }
    }
    
    # GSM Modem Configuration (Kali Linux optimized)
    GSM_MODEM = {
        'port': os.environ.get('GSM_MODEM_PORT', '/dev/ttyUSB0'),  # Linux default
        'baudrate': int(os.environ.get('GSM_MODEM_BAUDRATE', '115200')),
        'timeout': int(os.environ.get('GSM_MODEM_TIMEOUT', '30')),
        'pin': os.environ.get('GSM_MODEM_PIN'),
        'supports_spoofing': True
    }
    
    # Security and Compliance Settings
    SECURITY = {
        'jwt_secret_key': JWT_SECRET_KEY,
        'max_daily_sms': int(os.environ.get('MAX_DAILY_SMS', '100')),
        'max_hourly_sms': int(os.environ.get('MAX_HOURLY_SMS', '20')),
        'require_authorization': os.environ.get('REQUIRE_AUTHORIZATION', 'True').lower() == 'true',
        'authorized_users': os.environ.get('AUTHORIZED_USERS', 'admin').split(','),
        'authorized_domains': os.environ.get('AUTHORIZED_DOMAINS', 'localhost,127.0.0.1').split(','),
        'ip_whitelist': os.environ.get('IP_WHITELIST', '').split(',') if os.environ.get('IP_WHITELIST') else [],
        'ip_blacklist': os.environ.get('IP_BLACKLIST', '').split(',') if os.environ.get('IP_BLACKLIST') else [],
        'max_login_attempts': int(os.environ.get('MAX_LOGIN_ATTEMPTS', '5')),
        'lockout_duration_minutes': int(os.environ.get('LOCKOUT_DURATION_MINUTES', '30')),
        'session_timeout_hours': int(os.environ.get('SESSION_TIMEOUT_HOURS', '24')),
        'password_min_length': int(os.environ.get('PASSWORD_MIN_LENGTH', '12')),
        'default_admin_password': os.environ.get('DEFAULT_ADMIN_PASSWORD', 'infernox123!'),
        'encryption_key': os.environ.get('ENCRYPTION_KEY'),
        'enforce_session_ip': os.environ.get('ENFORCE_SESSION_IP', 'False').lower() == 'true',
        'block_private_ips': os.environ.get('BLOCK_PRIVATE_IPS', 'False').lower() == 'true',
        'sms_per_minute': int(os.environ.get('RATE_LIMIT_PER_MINUTE', '5')),
        'sms_per_hour': int(os.environ.get('RATE_LIMIT_PER_HOUR', '50')),
        'sms_per_day': int(os.environ.get('RATE_LIMIT_PER_DAY', '200')),
        'login_per_minute': int(os.environ.get('LOGIN_RATE_LIMIT', '5')),
        'api_per_minute': int(os.environ.get('API_RATE_LIMIT', '60'))
    }
    
    # Logging Configuration
    LOGGING = {
        'level': os.environ.get('LOG_LEVEL', 'INFO'),
        'file_path': os.environ.get('LOG_FILE_PATH', 'logs/sms_spoofing.log'),
        'max_file_size': int(os.environ.get('LOG_MAX_FILE_SIZE', '10485760')),  # 10MB
        'backup_count': int(os.environ.get('LOG_BACKUP_COUNT', '5')),
        'audit_file_path': os.environ.get('AUDIT_LOG_PATH', 'logs/audit.log')
    }
    
    # Rate Limiting
    RATE_LIMITING = {
        'enabled': True,
        'requests_per_minute': int(os.environ.get('RATE_LIMIT_PER_MINUTE', '10')),
        'requests_per_hour': int(os.environ.get('RATE_LIMIT_PER_HOUR', '100')),
        'requests_per_day': int(os.environ.get('RATE_LIMIT_PER_DAY', '500'))
    }
    
    # Legal and Compliance
    COMPLIANCE = {
        'require_consent_checkbox': True,
        'require_purpose_declaration': True,
        'allowed_purposes': [
            'security_testing',
            'penetration_testing', 
            'educational_research',
            'authorized_simulation',
            'compliance_testing'
        ],
        'prohibited_purposes': [
            'fraud',
            'harassment',
            'spam',
            'phishing',
            'identity_theft'
        ],
        'legal_disclaimer_required': True,
        'audit_trail_mandatory': True
    }

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    # Enhanced security for production
    SECURITY = {
        **Config.SECURITY,
        'max_daily_sms': 50,  # More restrictive in production
        'max_hourly_sms': 10,
        'require_2fa': True,
        'ip_whitelist_enabled': True,
        'authorized_ips': os.environ.get('AUTHORIZED_IPS', '').split(',')
    }

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test_sms_spoofing.db'
    
    # Relaxed limits for testing
    SECURITY = {
        **Config.SECURITY,
        'max_daily_sms': 10,
        'max_hourly_sms': 5,
        'require_authorization': False
    }

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])
