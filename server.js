// server.js - Combined Backend + Frontend Server for Chatti Platform
// This serves both the API and the static files

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serve static files from public directory

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
        redirectUri: process.env.XERO_REDIRECT_URI || 'https://your-app.onrender.com/api/xero/callback'
    }
};

// Store for demo purposes (use a database in production)
let dataStore = {
    customers: [],
    usage: {},
    rates: {}
};

// =================== FRONTEND ROUTES ===================

// Serve the main app
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// =================== API ROUTES ===================

// Test endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Chatti Platform API is running' });
});

// Login endpoint (simplified for demo)
app.post('/api/login', (req, res) => {
    const { email, password, role } = req.body;
    
    // Simple demo authentication
    if (email && password) {
        res.json({
            success: true,
            user: { email, role },
            token: 'demo-token-' + Date.now()
        });
    } else {
        res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
});

// =================== VONAGE ENDPOINTS ===================

// Get SMS usage summary
app.get('/api/vonage/usage/sms', async (req, res) => {
    try {
        const { month } = req.query;
        
        // For demo, return sample data
        // In production, call actual Vonage API
        const usage = {
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
        
        res.json({ success: true, data: usage });
    } catch (error) {
        console.error('Error fetching usage:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get customer SMS usage
app.get('/api/vonage/usage/customer/:customerId', async (req, res) => {
    try {
        const { customerId } = req.params;
        const { month } = req.query;
        
        // Demo data
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

// Get phone numbers by customer
app.get('/api/vonage/numbers/:customerId', async (req, res) => {
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

// =================== XERO ENDPOINTS ===================

// Get Xero auth URL
app.get('/api/xero/auth', (req, res) => {
    const authUrl = `https://login.xero.com/identity/connect/authorize?` +
        `response_type=code&` +
        `client_id=${config.xero.clientId}&` +
        `redirect_uri=${config.xero.redirectUri}&` +
        `scope=accounting.transactions accounting.contacts accounting.settings&` +
        `state=${Date.now()}`;
    
    res.json({ authUrl });
});

// Handle Xero callback
app.get('/api/xero/callback', async (req, res) => {
    try {
        const { code, state } = req.query;
        
        // Exchange code for token (simplified)
        console.log('Received Xero callback with code:', code);
        
        // Redirect to success page
        res.redirect('/?xero=connected');
    } catch (error) {
        console.error('Xero callback error:', error);
        res.redirect('/?xero=error');
    }
});

// Get Xero contacts
app.get('/api/xero/contacts', async (req, res) => {
    try {
        // Demo data
        const contacts = [
            { id: 'XERO-ABC123', name: 'Acme Corp', email: 'accounts@acme.com' },
            { id: 'XERO-DEF456', name: 'TechStart Inc', email: 'billing@techstart.com' }
        ];
        
        res.json({ success: true, data: contacts });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// =================== CUSTOMER MANAGEMENT ===================

// Get all customers
app.get('/api/customers', (req, res) => {
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

// Link customer accounts
app.post('/api/customers/link', (req, res) => {
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

// =================== PRODUCT & RATES ===================

// Get product mappings
app.get('/api/products/mappings', (req, res) => {
    const mappings = [
        { vonageProduct: 'SMS-AU', xeroItem: 'SMS Australia', type: 'SMS' },
        { vonageProduct: 'SMS-US', xeroItem: 'SMS United States', type: 'SMS' },
        { vonageProduct: 'NUM-AU', xeroItem: 'Phone Number AU', type: 'Number' }
    ];
    
    res.json({ success: true, data: mappings });
});

// Get customer rates
app.get('/api/customers/:customerId/rates', (req, res) => {
    const rates = {
        'SMS-AU': 0.08,
        'SMS-US': 0.01,
        'SMS-UK': 0.02,
        'NUM-AU': 10.00,
        'NUM-US': 5.00
    };
    
    res.json({ success: true, data: rates });
});

// =================== BILLING ===================

// Generate draft invoices
app.post('/api/billing/generate-invoices', (req, res) => {
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

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Chatti Platform running on port ${PORT}`);
    console.log(`Visit: http://localhost:${PORT}`);
});