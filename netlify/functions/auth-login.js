// Netlify Function for authentication
const jwt = require('jsonwebtoken');

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
    const { username, password } = JSON.parse(event.body);
    
    // Simple authentication (in production, use proper password hashing)
    const validUsers = {
      'admin': 'admin123!@#'
    };

    if (!validUsers[username] || validUsers[username] !== password) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Invalid credentials'
        })
      };
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        username: username,
        userId: 'admin_user',
        role: 'admin'
      },
      process.env.JWT_SECRET || 'infernox-jwt-secret-key',
      { expiresIn: '24h' }
    );

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        token: token,
        user: {
          username: username,
          role: 'admin'
        }
      })
    };

  } catch (error) {
    console.error('Login failed:', error);
    
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        success: false,
        error: 'Login failed'
      })
    };
  }
};
