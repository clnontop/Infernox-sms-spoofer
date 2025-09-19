# 🚀 Netlify Deployment Guide

## 📋 Overview
This guide explains how to deploy the Infernox SMS Spoofing System to Netlify with serverless functions for real SMS sending.

## 🔧 Prerequisites
- GitHub account
- Netlify account
- TextBee account with device ID: `23124RN87I`

## 📁 Project Structure for Netlify
```
infernox-sms-spoofer/
├── netlify/
│   └── functions/
│       ├── send-sms.js          # SMS sending function
│       └── auth-login.js        # Authentication function
├── templates/
│   ├── dashboard.html           # Main dashboard
│   └── login.html              # Login page
├── static/
│   ├── css/dashboard.css       # Styling
│   └── js/dashboard.js         # Frontend logic
├── netlify.toml                # Netlify configuration
├── package.json                # Node.js dependencies
└── README.md
```

## 🚀 Deployment Steps

### Step 1: Push to GitHub
```bash
git add .
git commit -m "Add Netlify serverless functions for SMS sending"
git push origin main
```

### Step 2: Connect to Netlify
1. Go to [netlify.com](https://netlify.com)
2. Click "New site from Git"
3. Connect your GitHub account
4. Select `clnontop/Infernox-sms-spoofer` repository
5. Configure build settings:
   - **Build command**: `npm install`
   - **Publish directory**: `.`
   - **Functions directory**: `netlify/functions`

### Step 3: Set Environment Variables
In Netlify dashboard → Site settings → Environment variables:

```bash
TEXTBEE_API_KEY=935d4fa0-7467-48df-8510-2c4bebfe2f8f
TEXTBEE_DEVICE_ID=23124RN87I
JWT_SECRET=infernox-jwt-secret-key-change-in-production
NODE_VERSION=18
```

### Step 4: Deploy
Click "Deploy site" - Netlify will:
1. Install Node.js dependencies
2. Build the serverless functions
3. Deploy your site with a random URL like: `https://amazing-site-123456.netlify.app`

## 🌐 Live Website Features

### What Works on Netlify:
- ✅ **Real SMS Sending**: Via TextBee API through your Redmi device
- ✅ **Authentication**: JWT-based login system
- ✅ **Modern Dashboard**: Full responsive interface
- ✅ **Sender ID Spoofing**: Custom sender names/numbers
- ✅ **Real-time Results**: Actual message IDs and delivery status

### API Endpoints:
- `https://yoursite.netlify.app/api/sms/send` - Send SMS
- `https://yoursite.netlify.app/api/auth/login` - User login
- `https://yoursite.netlify.app/dashboard` - Main dashboard
- `https://yoursite.netlify.app/login` - Login page

## 📱 How SMS Sending Works

### Process Flow:
1. **User fills SMS form** on dashboard
2. **Frontend sends request** to `/api/sms/send`
3. **Netlify function receives** request
4. **Function calls TextBee API** with your device ID
5. **Your Redmi phone sends** the actual SMS
6. **Real delivery confirmation** returned to user

### Example API Call:
```javascript
// Frontend makes this call:
fetch('/api/sms/send', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    to: '+1234567890',
    message: 'Hello from Infernox!',
    sender_id: 'COMPANY'
  })
})

// Netlify function processes and calls:
// POST https://api.textbee.dev/api/v1/gateway/devices/23124RN87I/send-sms
```

## 🔐 Security Features

### Authentication:
- JWT tokens for session management
- Secure login with admin credentials
- Token validation on protected routes

### SMS Security:
- Rate limiting (built into TextBee)
- Consent validation required
- Audit logging of all SMS attempts
- Legal compliance notices

## 🎯 Default Credentials
```
Username: admin
Password: admin123!@#
```

## ⚠️ Important Notes

### Legal Compliance:
- ✅ Only use for authorized security testing
- ✅ Get proper permission before sending SMS
- ✅ Comply with local telecommunications laws
- ✅ Document all testing activities

### TextBee Requirements:
- 📱 Your Redmi device must be online
- 📶 Active mobile connection required
- 🔗 TextBee app running in background
- 🆔 Valid device registration

### Cost Considerations:
- 💰 SMS charges apply through your mobile plan
- 📊 TextBee may have usage limits
- 🔄 Monitor your device's SMS usage

## 🔧 Troubleshooting

### Common Issues:
1. **SMS not sending**: Check if Redmi device is online
2. **Authentication fails**: Verify environment variables
3. **Function timeout**: TextBee API might be slow
4. **CORS errors**: Functions include proper headers

### Debug Steps:
1. Check Netlify function logs
2. Verify TextBee device status
3. Test API endpoints directly
4. Monitor network requests in browser

## 📈 Monitoring

### Netlify Analytics:
- Function invocation counts
- Error rates and response times
- Bandwidth usage

### SMS Tracking:
- Message delivery status
- Failed send attempts
- Cost per message

## 🎉 Success!

Once deployed, you'll have a **live SMS spoofing website** that:
- Sends real SMS through your Redmi device
- Works from any internet connection
- Has a professional interface
- Includes security features
- Supports sender ID spoofing

Your live site will be accessible at: `https://your-site-name.netlify.app`
