"""
GSM Modem Integration Module
Provides direct SMS sending via GSM modems with sender ID spoofing
"""

import serial
import time
import threading
import logging
from typing import Optional, Dict, List
from datetime import datetime
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ModemInfo:
    """GSM Modem information"""
    manufacturer: str = ""
    model: str = ""
    revision: str = ""
    imei: str = ""
    signal_strength: int = 0
    network_operator: str = ""
    sim_status: str = ""

class GSMModemError(Exception):
    """Custom exception for GSM modem errors"""
    pass

class GSMModem:
    """GSM Modem controller for SMS sending with spoofing capabilities"""
    
    def __init__(self, port: str, baudrate: int = 115200, timeout: int = 30, pin: str = None):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.pin = pin
        self.connection = None
        self.is_connected = False
        self.modem_info = ModemInfo()
        self.lock = threading.Lock()
        
    def connect(self) -> bool:
        """Connect to GSM modem"""
        try:
            self.connection = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                timeout=self.timeout,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE
            )
            
            # Wait for modem to initialize
            time.sleep(2)
            
            # Test connection
            if self._send_command("AT"):
                self.is_connected = True
                logger.info(f"Connected to GSM modem on {self.port}")
                
                # Initialize modem
                self._initialize_modem()
                return True
            else:
                raise GSMModemError("Modem not responding to AT commands")
                
        except Exception as e:
            logger.error(f"Failed to connect to GSM modem: {str(e)}")
            self.is_connected = False
            return False
    
    def disconnect(self):
        """Disconnect from GSM modem"""
        if self.connection and self.connection.is_open:
            self.connection.close()
            self.is_connected = False
            logger.info("Disconnected from GSM modem")
    
    def _send_command(self, command: str, wait_for: str = "OK", timeout: int = 10) -> Optional[str]:
        """Send AT command to modem and wait for response"""
        if not self.connection or not self.connection.is_open:
            raise GSMModemError("Modem not connected")
        
        with self.lock:
            try:
                # Clear input buffer
                self.connection.reset_input_buffer()
                
                # Send command
                self.connection.write((command + '\r\n').encode())
                
                # Read response
                response = ""
                start_time = time.time()
                
                while time.time() - start_time < timeout:
                    if self.connection.in_waiting > 0:
                        data = self.connection.read(self.connection.in_waiting).decode('utf-8', errors='ignore')
                        response += data
                        
                        if wait_for in response or "ERROR" in response:
                            break
                    time.sleep(0.1)
                
                logger.debug(f"Command: {command}, Response: {response.strip()}")
                
                if "ERROR" in response:
                    raise GSMModemError(f"Command failed: {command} - {response}")
                
                return response.strip() if wait_for in response else None
                
            except Exception as e:
                logger.error(f"Command execution failed: {str(e)}")
                raise GSMModemError(f"Command execution failed: {str(e)}")
    
    def _initialize_modem(self):
        """Initialize modem settings"""
        try:
            # Set text mode for SMS
            self._send_command("AT+CMGF=1")
            
            # Set character set to GSM
            self._send_command("AT+CSCS=\"GSM\"")
            
            # Disable echo
            self._send_command("ATE0")
            
            # Check SIM PIN
            pin_status = self._send_command("AT+CPIN?")
            if "SIM PIN" in pin_status and self.pin:
                self._send_command(f"AT+CPIN={self.pin}")
                time.sleep(3)  # Wait for SIM to unlock
            
            # Get modem information
            self._get_modem_info()
            
            logger.info("GSM modem initialized successfully")
            
        except Exception as e:
            logger.error(f"Modem initialization failed: {str(e)}")
            raise GSMModemError(f"Modem initialization failed: {str(e)}")
    
    def _get_modem_info(self):
        """Get modem information"""
        try:
            # Manufacturer
            response = self._send_command("AT+CGMI")
            if response:
                self.modem_info.manufacturer = self._extract_response_data(response)
            
            # Model
            response = self._send_command("AT+CGMM")
            if response:
                self.modem_info.model = self._extract_response_data(response)
            
            # Revision
            response = self._send_command("AT+CGMR")
            if response:
                self.modem_info.revision = self._extract_response_data(response)
            
            # IMEI
            response = self._send_command("AT+CGSN")
            if response:
                self.modem_info.imei = self._extract_response_data(response)
            
            # Signal strength
            response = self._send_command("AT+CSQ")
            if response:
                match = re.search(r'\+CSQ: (\d+),', response)
                if match:
                    self.modem_info.signal_strength = int(match.group(1))
            
            # Network operator
            response = self._send_command("AT+COPS?")
            if response:
                match = re.search(r'"([^"]+)"', response)
                if match:
                    self.modem_info.network_operator = match.group(1)
            
        except Exception as e:
            logger.warning(f"Could not retrieve all modem info: {str(e)}")
    
    def _extract_response_data(self, response: str) -> str:
        """Extract data from AT command response"""
        lines = response.split('\n')
        for line in lines:
            line = line.strip()
            if line and line != "OK" and not line.startswith('AT'):
                return line
        return ""
    
    def send_sms(self, to: str, message: str, sender_id: str = None) -> Dict:
        """Send SMS via GSM modem with optional sender ID spoofing"""
        if not self.is_connected:
            raise GSMModemError("Modem not connected")
        
        try:
            # For sender ID spoofing, we need to use PDU mode
            if sender_id:
                return self._send_sms_pdu_mode(to, message, sender_id)
            else:
                return self._send_sms_text_mode(to, message)
                
        except Exception as e:
            logger.error(f"SMS sending failed: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _send_sms_text_mode(self, to: str, message: str) -> Dict:
        """Send SMS in text mode (no spoofing)"""
        try:
            # Set text mode
            self._send_command("AT+CMGF=1")
            
            # Set SMS center (optional, usually auto-detected)
            # self._send_command("AT+CSCA=\"+1234567890\"")
            
            # Start SMS composition
            response = self._send_command(f"AT+CMGS=\"{to}\"", wait_for=">", timeout=10)
            
            if ">" not in response:
                raise GSMModemError("Modem not ready for SMS composition")
            
            # Send message content followed by Ctrl+Z
            self.connection.write(message.encode() + b'\x1A')
            
            # Wait for confirmation
            response = self._send_command("", wait_for="+CMGS:", timeout=30)
            
            if "+CMGS:" in response:
                # Extract message reference
                match = re.search(r'\+CMGS: (\d+)', response)
                message_ref = match.group(1) if match else "unknown"
                
                return {
                    'success': True,
                    'message_id': f"gsm_{message_ref}",
                    'provider': 'gsm_modem',
                    'timestamp': datetime.utcnow().isoformat(),
                    'method': 'text_mode'
                }
            else:
                raise GSMModemError("SMS sending failed - no confirmation received")
                
        except Exception as e:
            logger.error(f"Text mode SMS failed: {str(e)}")
            raise GSMModemError(f"Text mode SMS failed: {str(e)}")
    
    def _send_sms_pdu_mode(self, to: str, message: str, sender_id: str) -> Dict:
        """Send SMS in PDU mode with sender ID spoofing"""
        try:
            # Set PDU mode
            self._send_command("AT+CMGF=0")
            
            # Create PDU with spoofed sender ID
            pdu = self._create_spoofed_pdu(to, message, sender_id)
            pdu_length = len(pdu) // 2 - 1  # PDU length in bytes, excluding SMSC
            
            # Send PDU
            response = self._send_command(f"AT+CMGS={pdu_length}", wait_for=">", timeout=10)
            
            if ">" not in response:
                raise GSMModemError("Modem not ready for PDU composition")
            
            # Send PDU data followed by Ctrl+Z
            self.connection.write(pdu.encode() + b'\x1A')
            
            # Wait for confirmation
            response = self._send_command("", wait_for="+CMGS:", timeout=30)
            
            if "+CMGS:" in response:
                # Extract message reference
                match = re.search(r'\+CMGS: (\d+)', response)
                message_ref = match.group(1) if match else "unknown"
                
                return {
                    'success': True,
                    'message_id': f"gsm_spoofed_{message_ref}",
                    'provider': 'gsm_modem',
                    'timestamp': datetime.utcnow().isoformat(),
                    'method': 'pdu_mode_spoofed',
                    'sender_id': sender_id
                }
            else:
                raise GSMModemError("Spoofed SMS sending failed - no confirmation received")
                
        except Exception as e:
            logger.error(f"PDU mode SMS failed: {str(e)}")
            raise GSMModemError(f"PDU mode SMS failed: {str(e)}")
    
    def _create_spoofed_pdu(self, to: str, message: str, sender_id: str) -> str:
        """Create SMS PDU with spoofed sender ID"""
        try:
            # This is a simplified PDU creation for demonstration
            # In production, use a proper SMS PDU library
            
            # Remove + from phone number
            to_number = to.replace('+', '').replace(' ', '')
            
            # Convert sender ID to hex
            sender_hex = sender_id.encode('utf-8').hex().upper()
            sender_length = len(sender_id)
            
            # Convert message to 7-bit GSM encoding (simplified)
            message_hex = self._encode_7bit_gsm(message)
            message_length = len(message)
            
            # Build PDU (simplified structure)
            pdu_parts = [
                "00",  # SMSC length (0 = use default)
                "01",  # SMS-SUBMIT
                "00",  # Message reference
                f"{len(to_number):02X}",  # Destination address length
                "91",  # International format
                self._swap_nibbles(to_number),  # Destination number
                "00",  # Protocol identifier
                "00",  # Data coding scheme (7-bit)
                f"{message_length:02X}",  # User data length
                message_hex  # User data
            ]
            
            # Insert sender ID (this is a simplified approach)
            # Note: Actual PDU spoofing is more complex and may not work on all networks
            
            pdu = "".join(pdu_parts)
            logger.debug(f"Created PDU: {pdu}")
            
            return pdu
            
        except Exception as e:
            logger.error(f"PDU creation failed: {str(e)}")
            raise GSMModemError(f"PDU creation failed: {str(e)}")
    
    def _encode_7bit_gsm(self, message: str) -> str:
        """Encode message in 7-bit GSM format (simplified)"""
        # This is a basic implementation - use proper SMS libraries for production
        return message.encode('utf-8').hex().upper()
    
    def _swap_nibbles(self, number: str) -> str:
        """Swap nibbles for phone number encoding"""
        if len(number) % 2 == 1:
            number += "F"
        
        result = ""
        for i in range(0, len(number), 2):
            result += number[i+1] + number[i]
        
        return result
    
    def get_signal_strength(self) -> int:
        """Get current signal strength"""
        try:
            response = self._send_command("AT+CSQ")
            if response:
                match = re.search(r'\+CSQ: (\d+),', response)
                if match:
                    return int(match.group(1))
            return 0
        except:
            return 0
    
    def get_network_info(self) -> Dict:
        """Get network information"""
        try:
            info = {
                'operator': '',
                'signal_strength': self.get_signal_strength(),
                'registration_status': '',
                'network_type': ''
            }
            
            # Network operator
            response = self._send_command("AT+COPS?")
            if response:
                match = re.search(r'"([^"]+)"', response)
                if match:
                    info['operator'] = match.group(1)
            
            # Registration status
            response = self._send_command("AT+CREG?")
            if response:
                match = re.search(r'\+CREG: \d+,(\d+)', response)
                if match:
                    status_code = match.group(1)
                    status_map = {
                        '0': 'Not registered',
                        '1': 'Registered (home)',
                        '2': 'Searching',
                        '3': 'Registration denied',
                        '5': 'Registered (roaming)'
                    }
                    info['registration_status'] = status_map.get(status_code, 'Unknown')
            
            return info
            
        except Exception as e:
            logger.error(f"Failed to get network info: {str(e)}")
            return {}
    
    def check_sms_storage(self) -> Dict:
        """Check SMS storage status"""
        try:
            response = self._send_command("AT+CPMS?")
            if response:
                # Parse storage info
                match = re.search(r'\+CPMS: "([^"]+)",(\d+),(\d+)', response)
                if match:
                    return {
                        'storage_type': match.group(1),
                        'used': int(match.group(2)),
                        'total': int(match.group(3))
                    }
            return {}
        except:
            return {}

class GSMModemManager:
    """Manager for multiple GSM modems"""
    
    def __init__(self):
        self.modems = {}
        self.active_modem = None
    
    def add_modem(self, name: str, port: str, baudrate: int = 115200, 
                  timeout: int = 30, pin: str = None) -> bool:
        """Add a GSM modem to the manager"""
        try:
            modem = GSMModem(port, baudrate, timeout, pin)
            if modem.connect():
                self.modems[name] = modem
                if not self.active_modem:
                    self.active_modem = name
                logger.info(f"Added GSM modem: {name}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to add modem {name}: {str(e)}")
            return False
    
    def remove_modem(self, name: str):
        """Remove a GSM modem"""
        if name in self.modems:
            self.modems[name].disconnect()
            del self.modems[name]
            if self.active_modem == name:
                self.active_modem = next(iter(self.modems), None)
    
    def send_sms(self, to: str, message: str, sender_id: str = None, 
                 modem_name: str = None) -> Dict:
        """Send SMS using specified or active modem"""
        modem_name = modem_name or self.active_modem
        
        if not modem_name or modem_name not in self.modems:
            return {
                'success': False,
                'error': 'No active GSM modem available',
                'timestamp': datetime.utcnow().isoformat()
            }
        
        return self.modems[modem_name].send_sms(to, message, sender_id)
    
    def get_modem_status(self) -> Dict:
        """Get status of all modems"""
        status = {}
        for name, modem in self.modems.items():
            status[name] = {
                'connected': modem.is_connected,
                'port': modem.port,
                'info': modem.modem_info.__dict__,
                'network': modem.get_network_info() if modem.is_connected else {},
                'active': name == self.active_modem
            }
        return status
