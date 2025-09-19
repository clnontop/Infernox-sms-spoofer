// Netlify Function for SMS sending
const axios = require('axios');

exports.handler = async (event, context) => {
  // Enable CORS
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };

  // Handle preflight requests
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers,
      body: ''
    };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const { to, message, sender_id } = JSON.parse(event.body);
    
    // TextBee API configuration
    const TEXTBEE_API_KEY = process.env.TEXTBEE_API_KEY || '935d4fa0-7467-48df-8510-2c4bebfe2f8f';
    const TEXTBEE_DEVICE_ID = process.env.TEXTBEE_DEVICE_ID || '23124RN87I';
    
    // Send SMS via TextBee API
    const response = await axios.post(
      `https://api.textbee.dev/api/v1/gateway/devices/${TEXTBEE_DEVICE_ID}/send-sms`,
      {
        recipients: [to],
        message: message
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': TEXTBEE_API_KEY
        },
        timeout: 30000
      }
    );

    if (response.status === 200) {
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          success: true,
          message_id: response.data.id || `textbee_${Date.now()}`,
          provider: 'textbee',
          status: response.data.status || 'sent',
          cost: response.data.cost || 0.05,
          timestamp: new Date().toISOString()
        })
      };
    } else {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

  } catch (error) {
    console.error('SMS send failed:', error);
    
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        success: false,
        error: error.message || 'Failed to send SMS',
        provider: 'textbee'
      })
    };
  }
};
