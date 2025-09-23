// server.js - Combined Backend + Frontend Server for Chatti Platform with Security

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serve static files from public directory

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Users database (in production, store in actual database)
// IMPORTANT: Replace the password hash with your generated hash
const users = [
    {
        id: 1,
        email: 'admin@chatti.com',
        password: '$2b$10$izO0mAq30rYRQuNwpWm/0O73dDbF6LHzq81d57aq/cpVWDQ8dvrmW', // <-- REPLACE WITH YOUR GENERATED HASH
        role: 'admin',
        name: 'Admin User'
    }
    // Add more users as needed
];

// Configuration
const config = {
    vonage: {
        apiKey: process.env.VONAGE_API_KEY,
        apiSecret: process.env.VONAGE_API_SECRET,
        baseUrl: 'https://rest.nexmo.com'
    },
    xero: {
        clientId: process.env.XERO_CLIENT_ID,
        clientSecret: process.env.XERO_CLIENT_SECRET,
        redirectUri: process.env.XERO_REDIRECT_URI || 'https://chatti-platform.onrender.com/api/xero/callback'
    }
};

// Store for demo purposes (use a database in production)
let dataStore = {
    customers: [],
    usage: {},
    rates: {}
};

// =================== AUTHENTICATION MIDDLEWARE ===================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'Access denied - no token provided' 
        });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ 
                success: false, 
                message: 'Invalid or expired token' 
            });
        }
        req.user = user;
        next();
    });
}

// =================== FRONTEND ROUTES ===================

// Serve the main app
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// =================== AUTHENTICATION ROUTES ===================

// Login endpoint with real authentication
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        // Find user
        const user = users.find(u => u.email === email);
        
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }
        
        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }
        
        // Create JWT token
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            success: true,
            token,
            user: {
                email: user.email,
                role: user.role,
                name: user.name
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error during login' 
        });
    }
});

// Logout endpoint (optional - mainly handled client-side)
app.post('/api/logout', (req, res) => {
    res.json({ success: true, message: 'Logged out successfully' });
});

// =================== API ROUTES ===================

// Test endpoint (unprotected)
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Chatti Platform API is running' });
});

// =================== PROTECTED VONAGE ENDPOINTS ===================

// Get SMS usage summary (protected)
app.get('/api/vonage/usage/sms', authenticateToken, async (req, res) => {
    try {
        const { month } = req.query;
        
        // Check if we have real Vonage credentials
        if (!config.vonage.apiKey || !config.vonage.apiSecret) {
            // Return demo data if no credentials
            const demoUsage = {
                total: 45678,
                inbound: 12345,
                outbound: 33333,
                byCountry: [
                    { country: 'AU', code: '+61', inbound: 5000, outbound: 15000 },
                    { country: 'US', code: '+1', inbound: 3000, outbound: 8000 },
                    { country: 'UK', code: '+44', inbound: 2000, outbound: 6000 },
                    { country: 'SG', code: '+65', inbound: 2345, outbound: 4333 }
                ]
            };
            return res.json({ success: true, data: demoUsage, demo: true });
        }
        
        // Real Vonage API call
        // TODO: Implement actual Vonage API integration here
        const usage = {
            total: 0,
            inbound: 0,
            outbound: 0,
            byCountry: []
        };
        
        res.json({ success: true, data: usage });
    } catch (error) {
        console.error('Error fetching usage:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get customer SMS usage (protected)
app.get('/api/vonage/usage/customer/:customerId', authenticateToken, async (req, res) => {
    try {
        const { customerId } = req.params;
        const { month } = req.query;
        
        // Demo data for now
        const usage = {
            customerId,
            month: month || new Date().toISOString().slice(0, 7),
            inbound: 1230,
            outbound: 4200,
            total: 5430,
            byCountry: [
                { country: 'AU', inbound: 800, outbound: 3000 },
                { country: 'US', inbound: 430, outbound: 1200 }
            ]
        };
        
        res.json({ success: true, data: usage });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get phone numbers by customer (protected)
app.get('/api/vonage/numbers/:customerId', authenticateToken, async (req, res) => {
    try {
        const { customerId } = req.params;
        
        // Demo data
        const numbers = {
            AU: 3,
            US: 2,
            UK: 1,
            SG: 0
        };
        
        res.json({ success: true, data: numbers });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// =================== PROTECTED XERO ENDPOINTS ===================

// Get Xero auth URL (protected)
app.get('/api/xero/auth', authenticateToken, (req, res) => {
    const authUrl = `https://login.xero.com/identity/connect/authorize?` +
        `response_type=code&` +
        `client_id=${config.xero.clientId}&` +
        `redirect_uri=${config.xero.redirectUri}&` +
        `scope=accounting.transactions accounting.contacts accounting.settings&` +
        `state=${Date.now()}`;
    
    res.json({ authUrl });
});

// Handle Xero callback (this one is not protected as it's a callback)
app.get('/api/xero/callback', async (req, res) => {
    try {
        const { code, state } = req.query;
        
        // Exchange code for token (simplified)
        console.log('Received Xero callback with code:', code);
        
        // TODO: Implement actual token exchange
        
        // Redirect to success page
        res.redirect('/?xero=connected');
    } catch (error) {
        console.error('Xero callback error:', error);
        res.redirect('/?xero=error');
    }
});

// Get Xero contacts (protected)
app.get('/api/xero/contacts', authenticateToken, async (req, res) => {
    try {
        // Demo data for now
        const contacts = [
            { id: 'XERO-ABC123', name: 'Acme Corp', email: 'accounts@acme.com' },
            { id: 'XERO-DEF456', name: 'TechStart Inc', email: 'billing@techstart.com' }
        ];
        
        res.json({ success: true, data: contacts });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// =================== PROTECTED CUSTOMER MANAGEMENT ===================

// Get all customers (protected)
app.get('/api/customers', authenticateToken, (req, res) => {
    const customers = dataStore.customers.length > 0 ? dataStore.customers : [
        {
            id: 1,
            name: 'Acme Corp',
            vonageAccount: 'VON-12345',
            xeroContact: 'XERO-ABC123',
            currentSMS: 5430,
            numbers: { AU: 3, US: 2, UK: 1 }
        },
        {
            id: 2,
            name: 'TechStart Inc',
            vonageAccount: 'VON-12346',
            xeroContact: 'XERO-DEF456',
            currentSMS: 2100,
            numbers: { AU: 5, SG: 2 }
        }
    ];
    
    res.json({ success: true, data: customers });
});

// Link customer accounts (protected)
app.post('/api/customers/link', authenticateToken, (req, res) => {
    const { vonageAccount, xeroContact, customerName } = req.body;
    
    const newCustomer = {
        id: Date.now(),
        name: customerName,
        vonageAccount,
        xeroContact,
        createdAt: new Date().toISOString()
    };
    
    dataStore.customers.push(newCustomer);
    
    res.json({ success: true, data: newCustomer });
});

// =================== PROTECTED PRODUCT & RATES ===================

// Get product mappings (protected)
app.get('/api/products/mappings', authenticateToken, (req, res) => {
    const mappings = [
        { vonageProduct: 'SMS-AU', xeroItem: 'SMS Australia', type: 'SMS' },
        { vonageProduct: 'SMS-US', xeroItem: 'SMS United States', type: 'SMS' },
        { vonageProduct: 'NUM-AU', xeroItem: 'Phone Number AU', type: 'Number' }
    ];
    
    res.json({ success: true, data: mappings });
});

// Get customer rates (protected)
app.get('/api/customers/:customerId/rates', authenticateToken, (req, res) => {
    const rates = {
        'SMS-AU': 0.08,
        'SMS-US': 0.01,
        'SMS-UK': 0.02,
        'NUM-AU': 10.00,
        'NUM-US': 5.00
    };
    
    res.json({ success: true, data: rates });
});

// =================== PROTECTED BILLING ===================

// Generate draft invoices (protected)
app.post('/api/billing/generate-invoices', authenticateToken, (req, res) => {
    const { month } = req.body;
    
    // Demo invoice generation
    const invoices = [
        {
            id: 'INV-2024-001',
            customer: 'Acme Corp',
            amount: 543.00,
            status: 'draft',
            items: [
                { description: 'SMS - AU', quantity: 5000, rate: 0.08, total: 400 },
                { description: 'Phone Numbers - AU', quantity: 3, rate: 10, total: 30 }
            ]
        },
        {
            id: 'INV-2024-002',
            customer: 'TechStart Inc',
            amount: 210.00,
            status: 'draft'
        }
    ];
    
    res.json({ success: true, data: invoices });
});

// =================== ERROR HANDLING ===================

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// =================== START SERVER ===================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Chatti Platform running on port ${PORT}`);
    console.log(`Visit: http://localhost:${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    
    // Check for required environment variables
    if (!process.env.JWT_SECRET) {
        console.warn('⚠️  WARNING: Using default JWT secret. Set JWT_SECRET environment variable in production!');
    }
    if (!process.env.VONAGE_API_KEY) {
        console.warn('⚠️  WARNING: Vonage API credentials not set. Using demo data.');
    }
    if (!process.env.XERO_CLIENT_ID) {
        console.warn('⚠️  WARNING: Xero API credentials not set.');
    }
});