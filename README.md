# 🔥 Infernox - Advanced SMS Spoofing Framework

<div align="center">

![Infernox Logo](https://img.shields.io/badge/Infernox-SMS%20Spoofing%20Framework-red?style=for-the-badge&logo=fire)

[![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-Educational%20Use-green?style=flat-square)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-orange?style=flat-square&logo=shield)](README.md)
[![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=flat-square)](README.md)

**A comprehensive, enterprise-grade SMS spoofing framework designed for authorized security testing and penetration testing.**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [API](#-api-reference) • [Legal](#-legal-notice)

</div>

---

## ⚠️ **CRITICAL LEGAL NOTICE**

**🚨 THIS TOOL IS FOR AUTHORIZED TESTING PURPOSES ONLY 🚨**

### ✅ **Authorized Use Cases:**
- 🔒 **Security Testing** with proper authorization
- 🛡️ **Penetration Testing** in controlled environments  
- 🎓 **Educational Research** and cybersecurity training
- 📋 **Compliance Testing** for organizations
- 🔴 **Red Team Exercises** with written permission

### ❌ **STRICTLY PROHIBITED:**
- 🚫 Fraud, harassment, or illegal activities
- 🚫 Unauthorized testing without explicit permission
- 🚫 Phishing or social engineering attacks
- 🚫 Any activity violating local/international laws

**⚖️ Users are solely responsible for ensuring compliance with applicable laws and regulations.**

---

## 🚀 **Features**

### 📱 **SMS Capabilities**
- **Multi-Provider Support** - Vonage, ClickSend, Plivo, MessageBird, Twilio, Custom APIs
- **Sender ID Spoofing** - Full spoofing support across compatible providers
- **GSM Modem Integration** - Direct hardware control for maximum spoofing capability
- **Automatic Failover** - Seamless switching between providers
- **Bulk Operations** - Send multiple SMS with rate limiting
- **Real-time Tracking** - Delivery status and cost monitoring

### 🔒 **Enterprise Security**
- **JWT Authentication** - Secure token-based authentication
- **Role-Based Access Control** - Admin, Operator, User, ReadOnly roles
- **Advanced Rate Limiting** - Per-minute, hourly, and daily limits
- **IP Whitelisting/Blacklisting** - Network-level access control
- **Session Management** - Secure session handling with expiration
- **Input Validation** - Comprehensive sanitization and validation

### 📊 **Audit & Compliance**
- **Complete Audit Trail** - Every SMS operation logged
- **Encrypted Storage** - Message content encrypted at rest
- **Compliance Reports** - Detailed reporting for audits
- **Security Monitoring** - Real-time security event tracking
- **Data Retention** - Configurable retention policies
- **Export Capabilities** - CSV/JSON export for analysis

### 🛠️ **Technical Features**
- **RESTful API** - Clean, documented API endpoints
- **Modular Architecture** - Easy to extend and customize
- **Cross-Platform** - Windows, Linux, macOS support
- **Production Ready** - Enterprise-grade error handling
- **Comprehensive Logging** - Detailed application and security logs
- **Configuration Management** - Environment-based configuration

---

## 📋 **Requirements**

### System Requirements
- **Python 3.8+**
- **2GB RAM minimum** (4GB recommended)
- **500MB disk space**
- **Network connectivity** for SMS providers

### Supported SMS Providers
| Provider | Spoofing Support | Global Coverage | Notes |
|----------|------------------|-----------------|-------|
| **Vonage (Nexmo)** | ✅ Full | 🌍 Worldwide | Recommended |
| **ClickSend** | ✅ Full | 🌍 Worldwide | Good alternative |
| **Plivo** | ✅ Full | 🌍 Worldwide | High volume |
| **MessageBird** | ✅ Full | 🌍 Worldwide | EU focused |
| **Twilio** | ⚠️ Limited | 🌍 Worldwide | Verified numbers only |
| **Custom APIs** | ✅ Configurable | 🔧 Custom | Your own gateway |
| **GSM Modems** | ✅ Full | 📡 Hardware | Maximum control |

---

## 🚀 **Installation**

### Quick Start (Kali Linux Optimized)
```bash
# Clone the repository
git clone https://github.com/yourusername/infernox.git
cd infernox

# Make executable and run
chmod +x infernox.py
python3 infernox.py
```

### Manual Installation
```bash
# Install Python dependencies
pip install -r requirements.txt

# Create environment configuration
cp .env.example .env

# Edit configuration with your SMS provider credentials
nano .env

# Run the system
python app.py
```

### Docker Installation (Optional)
```bash
# Build Docker image
docker build -t infernox .

# Run container
docker run -p 5000:5000 -v $(pwd)/.env:/app/.env infernox
```

---

## ⚙️ **Configuration**

### Environment Setup
Create a `.env` file with your SMS provider credentials:

```bash
# SMS Provider Configuration
VONAGE_API_KEY=your_vonage_key
VONAGE_API_SECRET=your_vonage_secret

CLICKSEND_USERNAME=your_clicksend_username
CLICKSEND_API_KEY=your_clicksend_key

# GSM Modem (Kali Linux)
GSM_MODEM_PORT=/dev/ttyUSB0  # Linux device
GSM_MODEM_BAUDRATE=115200
GSM_MODEM_PIN=1234           # SIM PIN

# Security Settings
SECRET_KEY=your_secret_key
JWT_SECRET_KEY=your_jwt_key
MAX_DAILY_SMS=500            # Higher for Kali
REQUIRE_AUTHORIZATION=True

# Rate Limiting (Kali optimized)
RATE_LIMIT_PER_MINUTE=20
RATE_LIMIT_PER_HOUR=500
RATE_LIMIT_PER_DAY=2000
```

### GSM Modem Setup (Kali Linux)
For maximum spoofing capability, configure a GSM modem:

#### Kali Linux Setup
```bash
# 1. Check for USB GSM devices
lsusb | grep -i modem
ls /dev/ttyUSB* /dev/ttyACM*

# 2. Set permissions for current user
sudo usermod -a -G dialout $USER
sudo chmod 666 /dev/ttyUSB0

# 3. Test modem connection
minicom -D /dev/ttyUSB0 -b 115200
# Type: AT (should respond with OK)

# 4. Configure in .env file
GSM_MODEM_PORT=/dev/ttyUSB0
GSM_MODEM_BAUDRATE=115200
GSM_MODEM_PIN=1234
```

#### Supported GSM Modems
- **Huawei E3372, E8372** - Excellent spoofing support
- **ZTE MF79U, MF823** - Good compatibility  
- **Sierra Wireless** - Professional grade
- **Quectel modules** - Embedded solutions

---

## 📖 **Usage**

### Starting the System (Kali Linux)
```bash
# Run Infernox with Kali optimizations
python3 infernox.py

# Or run directly (basic mode)
python3 app.py
```

### API Access
- **Base URL:** `http://localhost:5000/api`
- **Authentication:** JWT Bearer token
- **Format:** JSON

### Basic SMS Sending
```python
import requests

# Login to get token
login_response = requests.post('http://localhost:5000/api/auth/login', json={
    'username': 'admin',
    'password': 'admin123!@#'
})
token = login_response.json()['token']

# Send spoofed SMS
sms_response = requests.post('http://localhost:5000/api/sms/send', 
    headers={'Authorization': f'Bearer {token}'},
    json={
        'to': '+1234567890',
        'message': 'Test message for authorized security testing',
        'sender_id': 'SPOOFED',
        'purpose': 'security_testing',
        'provider': 'vonage'
    }
)

print(sms_response.json())
```

---

## 🔌 **API Reference**

### Authentication

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123!@#"
}
```

**Response:**
```json
{
  "token": "jwt_token_here",
  "user": {
    "user_id": "admin",
    "username": "admin", 
    "role": "admin",
    "permissions": ["sms_send", "sms_spoof", "audit_view"]
  }
}
```

### SMS Operations

#### Send SMS
```http
POST /api/sms/send
Authorization: Bearer {jwt_token}
Content-Type: application/json

{
  "to": "+1234567890",
  "message": "Your message content",
  "sender_id": "SPOOFED_ID",
  "purpose": "security_testing",
  "provider": "vonage",
  "use_gsm": false
}
```

**Response:**
```json
{
  "success": true,
  "message_id": "msg_12345",
  "provider": "vonage",
  "cost": 0.05,
  "timestamp": "2024-01-01T12:00:00Z"
}
```

#### Get Providers
```http
GET /api/sms/providers
Authorization: Bearer {jwt_token}
```

### Audit & Compliance

#### Get Audit Records
```http
GET /api/audit/records?start_date=2024-01-01&limit=100
Authorization: Bearer {jwt_token}
```

#### Generate Compliance Report
```http
GET /api/audit/compliance-report?start_date=2024-01-01&end_date=2024-01-31
Authorization: Bearer {jwt_token}
```

---

## 🛡️ **Security Features**

### Authentication & Authorization
- **JWT Token Authentication** with configurable expiration
- **Role-Based Access Control** with granular permissions
- **Session Management** with IP validation
- **Multi-Factor Authentication** support (configurable)

### Rate Limiting & Protection
- **Advanced Rate Limiting** across multiple time windows
- **IP-based Restrictions** with whitelist/blacklist support
- **Suspicious Activity Detection** with automatic blocking
- **Request Validation** with comprehensive input sanitization

### Audit & Monitoring
- **Complete Audit Trail** of all system operations
- **Security Event Logging** with severity classification
- **Real-time Monitoring** of system health and security
- **Automated Alerting** for security incidents

---

## 🔧 **Advanced Configuration**

### Provider Priority
Configure provider failover order:
```python
# In config.py
PROVIDER_PRIORITY = ['vonage', 'clicksend', 'plivo', 'gsm_modem']
```

### Custom SMS Gateway
Add your own SMS gateway:
```python
# In sms_gateway.py
class CustomProvider(BaseSMSProvider):
    def send_sms(self, to, message, sender_id=None):
        # Your custom implementation
        pass
```

### Security Hardening
```bash
# Production security settings
REQUIRE_AUTHORIZATION=True
ENFORCE_SESSION_IP=True
BLOCK_PRIVATE_IPS=True
IP_WHITELIST=192.168.1.0/24
MAX_LOGIN_ATTEMPTS=3
LOCKOUT_DURATION_MINUTES=30
```

---

## 📊 **Monitoring & Maintenance**

### Log Files
- **Application Logs:** `logs/app.log`
- **Audit Logs:** `logs/audit.log`  
- **Security Logs:** `logs/security.log`

### Health Checks
```bash
# System status
curl -H "Authorization: Bearer $TOKEN" http://localhost:5000/api/system/status

# Provider status  
curl -H "Authorization: Bearer $TOKEN" http://localhost:5000/api/sms/providers
```

### Database Maintenance
```bash
# Cleanup old records
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:5000/api/system/cleanup
```

---

## 🚨 **Troubleshooting**

### Common Issues

#### SMS Provider Errors
```
Error: Authentication failed
Solution: Verify API credentials in .env file
```

#### GSM Modem Issues
```
Error: Could not connect to modem
Solutions:
- Check COM port/device path
- Install proper drivers
- Verify AT command support
- Check SIM card and PIN
```

#### Permission Errors
```
Error: Insufficient permissions
Solution: Check user role and permissions
```

### Debug Mode
```bash
# Enable debug logging
LOG_LEVEL=DEBUG python app.py

# Monitor logs
tail -f logs/app.log
```

---

## 🤝 **Contributing**

We welcome contributions that enhance security, add provider support, or improve compliance features:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit your changes** (`git commit -m 'Add amazing feature'`)
4. **Push to the branch** (`git push origin feature/amazing-feature`)
5. **Open a Pull Request**

### Contribution Guidelines
- Focus on security improvements
- Add comprehensive tests
- Update documentation
- Follow Python PEP 8 style guide
- Ensure legal compliance features

---

## 📄 **License**

This project is licensed under the **Educational Use License** - see the [LICENSE](LICENSE) file for details.

### Important Notes
- **Educational and authorized testing use only**
- **No warranty or liability provided**
- **Users responsible for legal compliance**
- **Not for commercial distribution without permission**

---

## 🙏 **Acknowledgments**

- **SMS Provider APIs** for enabling programmatic SMS sending
- **Security Research Community** for best practices and guidelines
- **Open Source Libraries** that make this project possible
- **Ethical Hackers** who use tools like this responsibly

---

## 📞 **Support & Contact**

### Getting Help
1. **Check Documentation** - Comprehensive guides included
2. **Review Issues** - Search existing GitHub issues
3. **Create Issue** - Report bugs or request features
4. **Security Contact** - Report security issues privately

### Responsible Disclosure
If you discover security vulnerabilities, please report them responsibly:
- **Email:** security@yourproject.com
- **PGP Key:** Available on request
- **Response Time:** 48 hours for acknowledgment

---

<div align="center">

### ⭐ **Star this project if you find it useful!**

**Remember: With great power comes great responsibility. Use Infernox ethically and legally!**

[![GitHub stars](https://img.shields.io/github/stars/yourusername/infernox?style=social)](https://github.com/yourusername/infernox/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/yourusername/infernox?style=social)](https://github.com/yourusername/infernox/network)

</div>

---

**Disclaimer:** The developers and contributors of Infernox are not responsible for any misuse of this tool. Users assume full responsibility for ensuring legal compliance and ethical use in their jurisdiction.
