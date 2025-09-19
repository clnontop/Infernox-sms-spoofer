"""
SMS Gateway Integration Module
Supports multiple SMS providers with sender ID spoofing capabilities
"""

import requests
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod

# Optional SMS provider imports - gracefully handle missing packages
try:
    from twilio.rest import Client as TwilioClient
    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False

try:
    from vonage import Client as VonageClient, Sms
    VONAGE_AVAILABLE = True
except ImportError:
    VONAGE_AVAILABLE = False

try:
    import clicksend_client
    from clicksend_client.rest import ApiException
    CLICKSEND_AVAILABLE = True
except ImportError:
    CLICKSEND_AVAILABLE = False

try:
    import plivo
    PLIVO_AVAILABLE = True
except ImportError:
    PLIVO_AVAILABLE = False

try:
    import messagebird
    MESSAGEBIRD_AVAILABLE = True
except ImportError:
    MESSAGEBIRD_AVAILABLE = False

logger = logging.getLogger(__name__)

class SMSResult:
    """Standardized SMS sending result"""
    def __init__(self, success: bool, message_id: str = None, error: str = None, 
                 provider: str = None, cost: float = None, status: str = None):
        self.success = success
        self.message_id = message_id
        self.error = error
        self.provider = provider
        self.cost = cost
        self.status = status
        self.timestamp = datetime.utcnow()
    
    def to_dict(self):
        return {
            'success': self.success,
            'message_id': self.message_id,
            'error': self.error,
            'provider': self.provider,
            'cost': self.cost,
            'status': self.status,
            'timestamp': self.timestamp.isoformat()
        }

class BaseSMSProvider(ABC):
    """Abstract base class for SMS providers"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.name = self.__class__.__name__.lower().replace('provider', '')
    
    @abstractmethod
    def send_sms(self, to: str, message: str, sender_id: str = None) -> SMSResult:
        """Send SMS with optional sender ID spoofing"""
        pass
    
    @abstractmethod
    def supports_spoofing(self) -> bool:
        """Check if provider supports sender ID spoofing"""
        pass
    
    def validate_phone_number(self, phone: str) -> bool:
        """Basic phone number validation"""
        try:
            # Try to use phonenumbers if available
            import phonenumbers
            parsed = phonenumbers.parse(phone, None)
            return phonenumbers.is_valid_number(parsed)
        except ImportError:
            # Fallback to basic validation
            import re
            # Basic international phone number pattern
            pattern = r'^\+?[1-9]\d{1,14}$'
            return bool(re.match(pattern, phone.replace(' ', '').replace('-', '')))

class TwilioProvider(BaseSMSProvider):
    """Twilio SMS Provider (Limited spoofing support)"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        if not TWILIO_AVAILABLE:
            raise ImportError("Twilio package not installed")
        self.client = TwilioClient(
            config['account_sid'], 
            config['auth_token']
        )
    
    def send_sms(self, to: str, message: str, sender_id: str = None) -> SMSResult:
        try:
            # Twilio requires verified sender IDs
            from_number = sender_id or self.config.get('default_from_number')
            
            message_obj = self.client.messages.create(
                body=message,
                from_=from_number,
                to=to
            )
            
            return SMSResult(
                success=True,
                message_id=message_obj.sid,
                provider='twilio',
                status=message_obj.status
            )
        except Exception as e:
            logger.error(f"Twilio SMS failed: {str(e)}")
            return SMSResult(success=False, error=str(e), provider='twilio')
    
    def supports_spoofing(self) -> bool:
        return False  # Twilio requires verified sender IDs

class VonageProvider(BaseSMSProvider):
    """Vonage (Nexmo) SMS Provider with spoofing support"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.client = VonageClient(
            key=config['api_key'],
            secret=config['api_secret']
        )
    
    def send_sms(self, to: str, message: str, sender_id: str = None) -> SMSResult:
        try:
            sms = Sms(self.client)
            
            response = sms.send_message({
                'from': sender_id or 'SMS',
                'to': to,
                'text': message
            })
            
            if response['messages'][0]['status'] == '0':
                return SMSResult(
                    success=True,
                    message_id=response['messages'][0]['message-id'],
                    provider='vonage',
                    cost=float(response['messages'][0]['message-price'])
                )
            else:
                return SMSResult(
                    success=False,
                    error=response['messages'][0]['error-text'],
                    provider='vonage'
                )
        except Exception as e:
            logger.error(f"Vonage SMS failed: {str(e)}")
            return SMSResult(success=False, error=str(e), provider='vonage')
    
    def supports_spoofing(self) -> bool:
        return True

class ClickSendProvider(BaseSMSProvider):
    """ClickSend SMS Provider with spoofing support"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        configuration = clicksend_client.Configuration()
        configuration.username = config['username']
        configuration.password = config['api_key']
        self.api_client = clicksend_client.ApiClient(configuration)
        self.sms_api = clicksend_client.SMSApi(self.api_client)
    
    def send_sms(self, to: str, message: str, sender_id: str = None) -> SMSResult:
        try:
            sms_message = clicksend_client.SmsMessage(
                source="sdk",
                body=message,
                to=to,
                from_=sender_id or "SMS"
            )
            
            sms_messages = clicksend_client.SmsMessageCollection(
                messages=[sms_message]
            )
            
            response = self.sms_api.sms_send_post(sms_messages)
            
            if response.response_code == "SUCCESS":
                message_data = response.data.messages[0]
                return SMSResult(
                    success=True,
                    message_id=message_data.message_id,
                    provider='clicksend',
                    cost=message_data.message_price,
                    status=message_data.status
                )
            else:
                return SMSResult(
                    success=False,
                    error=response.response_msg,
                    provider='clicksend'
                )
        except ApiException as e:
            logger.error(f"ClickSend SMS failed: {str(e)}")
            return SMSResult(success=False, error=str(e), provider='clicksend')
    
    def supports_spoofing(self) -> bool:
        return True

class PlivoProvider(BaseSMSProvider):
    """Plivo SMS Provider with spoofing support"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.client = plivo.RestClient(
            config['auth_id'],
            config['auth_token']
        )
    
    def send_sms(self, to: str, message: str, sender_id: str = None) -> SMSResult:
        try:
            response = self.client.messages.create(
                src=sender_id or 'PLIVO',
                dst=to,
                text=message
            )
            
            return SMSResult(
                success=True,
                message_id=response.message_uuid,
                provider='plivo',
                status='sent'
            )
        except Exception as e:
            logger.error(f"Plivo SMS failed: {str(e)}")
            return SMSResult(success=False, error=str(e), provider='plivo')
    
    def supports_spoofing(self) -> bool:
        return True

class MessageBirdProvider(BaseSMSProvider):
    """MessageBird SMS Provider with spoofing support"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.client = messagebird.Client(config['access_key'])
    
    def send_sms(self, to: str, message: str, sender_id: str = None) -> SMSResult:
        try:
            response = self.client.message_create(
                sender_id or 'SMS',
                to,
                message
            )
            
            return SMSResult(
                success=True,
                message_id=response.id,
                provider='messagebird',
                status='sent'
            )
        except Exception as e:
            logger.error(f"MessageBird SMS failed: {str(e)}")
            return SMSResult(success=False, error=str(e), provider='messagebird')
    
    def supports_spoofing(self) -> bool:
        return True

class TextBeeProvider(BaseSMSProvider):
    """TextBee SMS Provider with full spoofing support"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.api_key = config['api_key']
        self.device_id = config['device_id']
        self.base_url = 'https://api.textbee.dev/api/v1'
    
    def send_sms(self, to: str, message: str, sender_id: str = None) -> SMSResult:
        try:
            # TextBee API implementation
            url = f"{self.base_url}/gateway/devices/{self.device_id}/send-sms"
            
            payload = {
                'recipients': [to],
                'message': message
            }
            
            headers = {
                'Content-Type': 'application/json',
                'x-api-key': self.api_key
            }
            
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return SMSResult(
                    success=True,
                    message_id=data.get('id', f'textbee_{datetime.now().timestamp()}'),
                    provider='textbee',
                    status=data.get('status', 'sent'),
                    cost=data.get('cost', 0.0)
                )
            else:
                error_msg = f"HTTP {response.status_code}"
                try:
                    error_data = response.json()
                    error_msg += f": {error_data.get('message', response.text)}"
                except:
                    error_msg += f": {response.text}"
                
                return SMSResult(
                    success=False,
                    error=error_msg,
                    provider='textbee'
                )
        except Exception as e:
            logger.error(f"TextBee SMS failed: {str(e)}")
            return SMSResult(success=False, error=str(e), provider='textbee')
    
    def supports_spoofing(self) -> bool:
        return True  # TextBee supports sender ID spoofing

class CustomGatewayProvider(BaseSMSProvider):
    """Custom SMS Gateway Provider for specialized APIs"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.api_url = config['api_url']
        self.api_key = config['api_key']
    
    def send_sms(self, to: str, message: str, sender_id: str = None) -> SMSResult:
        try:
            # Generic HTTP API implementation
            payload = {
                'to': to,
                'message': message,
                'from': sender_id or 'SMS',
                'api_key': self.api_key
            }
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.api_key}'
            }
            
            response = requests.post(
                self.api_url,
                json=payload,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return SMSResult(
                    success=True,
                    message_id=data.get('message_id', 'custom_' + str(datetime.now().timestamp())),
                    provider='custom_gateway',
                    status=data.get('status', 'sent')
                )
            else:
                return SMSResult(
                    success=False,
                    error=f"HTTP {response.status_code}: {response.text}",
                    provider='custom_gateway'
                )
        except Exception as e:
            logger.error(f"Custom Gateway SMS failed: {str(e)}")
            return SMSResult(success=False, error=str(e), provider='custom_gateway')
    
    def supports_spoofing(self) -> bool:
        return True

class SMSGatewayManager:
    """Manages multiple SMS providers and routing"""
    
    def __init__(self, providers_config: Dict):
        self.providers = {}
        self.initialize_providers(providers_config)
    
    def initialize_providers(self, config: Dict):
        """Initialize all configured SMS providers"""
        provider_classes = {
            'twilio': (TwilioProvider, TWILIO_AVAILABLE),
            'vonage': (VonageProvider, VONAGE_AVAILABLE),
            'clicksend': (ClickSendProvider, CLICKSEND_AVAILABLE),
            'plivo': (PlivoProvider, PLIVO_AVAILABLE),
            'messagebird': (MessageBirdProvider, MESSAGEBIRD_AVAILABLE),
            'textbee': (TextBeeProvider, True),  # Always available - uses requests
            'custom_gateway': (CustomGatewayProvider, True)  # Always available
        }
        
        for provider_name, provider_config in config.items():
            if provider_name in provider_classes:
                provider_class, available = provider_classes[provider_name]
                
                if not available:
                    logger.warning(f"{provider_name} package not installed - skipping")
                    continue
                    
                if self._is_provider_configured(provider_config):
                    try:
                        self.providers[provider_name] = provider_class(provider_config)
                        logger.info(f"Initialized {provider_name} SMS provider")
                    except Exception as e:
                        logger.error(f"Failed to initialize {provider_name}: {str(e)}")
                else:
                    logger.warning(f"{provider_name} not properly configured - skipping")
    
    def _is_provider_configured(self, config: Dict) -> bool:
        """Check if provider has required configuration"""
        required_keys = {
            'twilio': ['account_sid', 'auth_token'],
            'vonage': ['api_key', 'api_secret'],
            'clicksend': ['username', 'api_key'],
            'plivo': ['auth_id', 'auth_token'],
            'messagebird': ['access_key'],
            'textbee': ['api_key', 'device_id'],
            'custom_gateway': ['api_url', 'api_key']
        }
        
        for provider, keys in required_keys.items():
            if any(key in config for key in keys):
                return all(config.get(key) for key in keys if key in config)
        return False
    
    def get_spoofing_providers(self) -> List[str]:
        """Get list of providers that support sender ID spoofing"""
        return [name for name, provider in self.providers.items() 
                if provider.supports_spoofing()]
    
    def send_sms(self, to: str, message: str, sender_id: str = None, 
                 preferred_provider: str = None) -> SMSResult:
        """Send SMS using specified or best available provider"""
        
        # Validate inputs
        if not to or not message:
            return SMSResult(success=False, error="Missing required parameters")
        
        # Choose provider
        if preferred_provider and preferred_provider in self.providers:
            provider = self.providers[preferred_provider]
        else:
            # Auto-select best provider for spoofing
            if sender_id:
                spoofing_providers = self.get_spoofing_providers()
                if spoofing_providers:
                    provider = self.providers[spoofing_providers[0]]
                else:
                    return SMSResult(
                        success=False, 
                        error="No providers support sender ID spoofing"
                    )
            else:
                # Use any available provider
                if self.providers:
                    provider = list(self.providers.values())[0]
                else:
                    return SMSResult(success=False, error="No SMS providers configured")
        
        # Send SMS
        try:
            result = provider.send_sms(to, message, sender_id)
            logger.info(f"SMS sent via {provider.name}: {result.success}")
            return result
        except Exception as e:
            logger.error(f"SMS sending failed: {str(e)}")
            return SMSResult(success=False, error=str(e), provider=provider.name)
    
    def get_provider_status(self) -> Dict:
        """Get status of all configured providers"""
        status = {}
        for name, provider in self.providers.items():
            status[name] = {
                'configured': True,
                'supports_spoofing': provider.supports_spoofing(),
                'class': provider.__class__.__name__
            }
        return status
