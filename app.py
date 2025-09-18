"""
Main Flask Application for SMS Spoofing System
Integrates all components: SMS gateways, GSM modems, security, audit logging
"""

from flask import Flask, request, jsonify, render_template, g
from flask_cors import CORS
import os
import logging
import uuid
from datetime import datetime
from typing import Dict, Any
import json

# Import our custom modules
from config import get_config
from sms_gateway import SMSGatewayManager, SMSResult
from gsm_modem import GSMModemManager
from audit_logger import AuditLogger, SMSAuditRecord, ComplianceChecker
from security_manager import SecurityManager, require_auth, require_rate_limit

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def create_app():
    """Application factory"""
    app = Flask(__name__)
    
    # Load configuration
    config = get_config()
    app.config.from_object(config)
    
    # Enable CORS
    CORS(app, origins=app.config.get('ALLOWED_ORIGINS', ['*']))
    
    # Initialize components
    sms_gateway_manager = SMSGatewayManager(app.config['SMS_PROVIDERS'])
    gsm_modem_manager = GSMModemManager()
    audit_logger = AuditLogger(app.config['LOGGING'])
    compliance_checker = ComplianceChecker(app.config['COMPLIANCE'])
    security_manager = SecurityManager(app.config['SECURITY'])
    
    # Initialize GSM modems if configured
    if app.config['GSM_MODEM']['port']:
        gsm_modem_manager.add_modem(
            'primary',
            app.config['GSM_MODEM']['port'],
            app.config['GSM_MODEM']['baudrate'],
            app.config['GSM_MODEM']['timeout'],
            app.config['GSM_MODEM']['pin']
        )
    
    # Store managers in app context
    app.sms_gateway_manager = sms_gateway_manager
    app.gsm_modem_manager = gsm_modem_manager
    app.audit_logger = audit_logger
    app.compliance_checker = compliance_checker
    app.security_manager = security_manager
    
    @app.before_request
    def before_request():
        """Pre-request security checks"""
        # Check IP security
        ip_check = security_manager.check_ip_security(request.remote_addr)
        if not ip_check['allowed']:
            logger.warning(f"Blocked request from {request.remote_addr}: {ip_check['reason']}")
            return jsonify({'error': 'Access denied', 'reason': ip_check['reason']}), 403
        
        # Log request for audit
        g.request_id = str(uuid.uuid4())
        g.request_start_time = datetime.utcnow()
    
    @app.after_request
    def after_request(response):
        """Post-request logging"""
        # Log API access
        if request.endpoint and not request.endpoint.startswith('static'):
            logger.info(f"API Access: {request.method} {request.path} - {response.status_code} - {request.remote_addr}")
        
        return response
    
    # Authentication Routes
    @app.route('/api/auth/register', methods=['POST'])
    def register():
        """Register new user"""
        try:
            data = request.get_json()
            
            # Validate required fields
            required_fields = ['username', 'email', 'password']
            if not all(field in data for field in required_fields):
                return jsonify({'error': 'Missing required fields'}), 400
            
            # Create user
            result = security_manager.create_user(
                data['username'],
                data['email'],
                data['password'],
                data.get('role', 'user')
            )
            
            if result['success']:
                return jsonify({'message': 'User created successfully', 'user_id': result['user_id']}), 201
            else:
                return jsonify({'error': result['error'], 'details': result.get('details')}), 400
                
        except Exception as e:
            logger.error(f"Registration failed: {str(e)}")
            return jsonify({'error': 'Registration failed'}), 500
    
    @app.route('/api/auth/login', methods=['POST'])
    def login():
        """User login"""
        try:
            data = request.get_json()
            
            if not data.get('username') or not data.get('password'):
                return jsonify({'error': 'Username and password required'}), 400
            
            result = security_manager.authenticate_user(
                data['username'],
                data['password'],
                request.remote_addr,
                request.headers.get('User-Agent', '')
            )
            
            if result['success']:
                return jsonify({
                    'token': result['token'],
                    'user': {
                        'user_id': result['user_id'],
                        'username': result['username'],
                        'role': result['role'],
                        'permissions': result['permissions']
                    }
                }), 200
            else:
                return jsonify({'error': result['error']}), 401
                
        except Exception as e:
            logger.error(f"Login failed: {str(e)}")
            return jsonify({'error': 'Login failed'}), 500
    
    @app.route('/api/auth/logout', methods=['POST'])
    @require_auth()
    def logout():
        """User logout"""
        try:
            security_manager.logout_user(g.current_user['session_id'])
            return jsonify({'message': 'Logged out successfully'}), 200
        except Exception as e:
            logger.error(f"Logout failed: {str(e)}")
            return jsonify({'error': 'Logout failed'}), 500
    
    # SMS Sending Routes
    @app.route('/api/sms/send', methods=['POST'])
    @require_auth('sms_send')
    @require_rate_limit('sms')
    def send_sms():
        """Send SMS with optional spoofing"""
        try:
            data = request.get_json()
            
            # Validate required fields
            required_fields = ['to', 'message']
            if not all(field in data for field in required_fields):
                return jsonify({'error': 'Missing required fields: to, message'}), 400
            
            to_number = data['to']
            message = data['message']
            sender_id = data.get('sender_id')
            purpose = data.get('purpose', 'testing')
            provider = data.get('provider')
            use_gsm = data.get('use_gsm', False)
            
            # Check spoofing permission
            if sender_id and not security_manager.check_permission(g.current_user['user_id'], 'sms_spoof'):
                return jsonify({'error': 'Insufficient permissions for sender ID spoofing'}), 403
            
            # Compliance check
            compliance_violations = compliance_checker.check_message_compliance(message, purpose)
            if compliance_violations:
                audit_logger.log_sms_attempt(SMSAuditRecord(
                    timestamp=datetime.utcnow(),
                    request_id=g.request_id,
                    user_id=g.current_user['user_id'],
                    user_ip=request.remote_addr,
                    recipient_number=to_number,
                    sender_id=sender_id or 'default',
                    message_content=message,
                    message_hash='',
                    provider='compliance_check',
                    success=False,
                    message_id=None,
                    error_message=f"Compliance violations: {', '.join(compliance_violations)}",
                    purpose=purpose,
                    authorization_level=g.current_user['role'],
                    compliance_flags=compliance_violations,
                    cost=None,
                    session_id=g.current_user['session_id'],
                    user_agent=request.headers.get('User-Agent', '')
                ))
                
                return jsonify({
                    'error': 'Message violates compliance policies',
                    'violations': compliance_violations
                }), 400
            
            # Send SMS
            if use_gsm:
                # Use GSM modem
                result_dict = gsm_modem_manager.send_sms(to_number, message, sender_id)
                result = SMSResult(
                    success=result_dict['success'],
                    message_id=result_dict.get('message_id'),
                    error=result_dict.get('error'),
                    provider='gsm_modem'
                )
            else:
                # Use SMS gateway
                result = sms_gateway_manager.send_sms(to_number, message, sender_id, provider)
            
            # Log audit record
            audit_logger.log_sms_attempt(SMSAuditRecord(
                timestamp=datetime.utcnow(),
                request_id=g.request_id,
                user_id=g.current_user['user_id'],
                user_ip=request.remote_addr,
                recipient_number=to_number,
                sender_id=sender_id or 'default',
                message_content=message,
                message_hash='',
                provider=result.provider,
                success=result.success,
                message_id=result.message_id,
                error_message=result.error,
                purpose=purpose,
                authorization_level=g.current_user['role'],
                compliance_flags=[],
                cost=result.cost,
                session_id=g.current_user['session_id'],
                user_agent=request.headers.get('User-Agent', '')
            ))
            
            if result.success:
                return jsonify({
                    'success': True,
                    'message_id': result.message_id,
                    'provider': result.provider,
                    'cost': result.cost,
                    'timestamp': result.timestamp.isoformat()
                }), 200
            else:
                return jsonify({
                    'success': False,
                    'error': result.error,
                    'provider': result.provider
                }), 400
                
        except Exception as e:
            logger.error(f"SMS sending failed: {str(e)}")
            return jsonify({'error': 'SMS sending failed', 'details': str(e)}), 500
    
    @app.route('/api/sms/providers', methods=['GET'])
    @require_auth()
    def get_providers():
        """Get available SMS providers"""
        try:
            gateway_status = sms_gateway_manager.get_provider_status()
            gsm_status = gsm_modem_manager.get_modem_status()
            
            return jsonify({
                'gateways': gateway_status,
                'gsm_modems': gsm_status,
                'spoofing_providers': sms_gateway_manager.get_spoofing_providers()
            }), 200
            
        except Exception as e:
            logger.error(f"Failed to get providers: {str(e)}")
            return jsonify({'error': 'Failed to get providers'}), 500
    
    # Audit and Compliance Routes
    @app.route('/api/audit/records', methods=['GET'])
    @require_auth('audit_view')
    def get_audit_records():
        """Get audit records with filtering"""
        try:
            user_id = request.args.get('user_id')
            start_date = request.args.get('start_date')
            end_date = request.args.get('end_date')
            limit = int(request.args.get('limit', 100))
            
            # Parse dates
            start_dt = datetime.fromisoformat(start_date) if start_date else None
            end_dt = datetime.fromisoformat(end_date) if end_date else None
            
            records = audit_logger.get_audit_records(user_id, start_dt, end_dt, limit)
            
            return jsonify({
                'records': records,
                'count': len(records)
            }), 200
            
        except Exception as e:
            logger.error(f"Failed to get audit records: {str(e)}")
            return jsonify({'error': 'Failed to get audit records'}), 500
    
    @app.route('/api/audit/security-events', methods=['GET'])
    @require_auth('audit_view')
    def get_security_events():
        """Get security events"""
        try:
            severity = request.args.get('severity')
            hours = int(request.args.get('hours', 24))
            
            events = audit_logger.get_security_events(severity, hours)
            
            return jsonify({
                'events': events,
                'count': len(events)
            }), 200
            
        except Exception as e:
            logger.error(f"Failed to get security events: {str(e)}")
            return jsonify({'error': 'Failed to get security events'}), 500
    
    @app.route('/api/audit/compliance-report', methods=['GET'])
    @require_auth('audit_view')
    def generate_compliance_report():
        """Generate compliance report"""
        try:
            start_date = request.args.get('start_date')
            end_date = request.args.get('end_date')
            
            if not start_date or not end_date:
                return jsonify({'error': 'start_date and end_date required'}), 400
            
            start_dt = datetime.fromisoformat(start_date)
            end_dt = datetime.fromisoformat(end_date)
            
            report = audit_logger.generate_compliance_report(start_dt, end_dt)
            
            return jsonify(report), 200
            
        except Exception as e:
            logger.error(f"Failed to generate compliance report: {str(e)}")
            return jsonify({'error': 'Failed to generate compliance report'}), 500
    
    # System Management Routes
    @app.route('/api/system/status', methods=['GET'])
    @require_auth()
    def system_status():
        """Get system status"""
        try:
            return jsonify({
                'status': 'operational',
                'timestamp': datetime.utcnow().isoformat(),
                'components': {
                    'sms_gateways': len(sms_gateway_manager.providers),
                    'gsm_modems': len(gsm_modem_manager.modems),
                    'active_sessions': len([s for s in security_manager.sessions.values() if s.is_active])
                },
                'version': '1.0.0'
            }), 200
            
        except Exception as e:
            logger.error(f"Failed to get system status: {str(e)}")
            return jsonify({'error': 'Failed to get system status'}), 500
    
    @app.route('/api/system/cleanup', methods=['POST'])
    @require_auth('system_config')
    def system_cleanup():
        """Perform system cleanup"""
        try:
            # Cleanup expired sessions
            security_manager.cleanup_expired_sessions()
            
            # Cleanup old audit records
            audit_logger.cleanup_old_records()
            
            return jsonify({'message': 'System cleanup completed'}), 200
            
        except Exception as e:
            logger.error(f"System cleanup failed: {str(e)}")
            return jsonify({'error': 'System cleanup failed'}), 500
    
    # Web Interface Routes
    @app.route('/')
    def index():
        """Main web interface"""
        return render_template('dashboard.html')
    
    @app.route('/login')
    def login_page():
        """Login page"""
        return render_template('login.html')
    
    @app.route('/dashboard')
    def dashboard():
        """Dashboard page"""
        return render_template('dashboard.html')
    
    # Error Handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Endpoint not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {str(error)}")
        return jsonify({'error': 'Internal server error'}), 500
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({'error': 'Access forbidden'}), 403
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({'error': 'Unauthorized access'}), 401
    
    return app

def main():
    """Main entry point"""
    # Create logs directory
    os.makedirs('logs', exist_ok=True)
    
    # Create Flask app
    app = create_app()
    
    # Get configuration
    config = get_config()
    
    # Run application
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', 5000))
    debug = config.DEBUG
    
    logger.info(f"Starting SMS Spoofing System on {host}:{port}")
    logger.info(f"Debug mode: {debug}")
    
    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    main()
