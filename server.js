// server.js - Combined Backend + Frontend Server for Chatti Platform with Security and Vonage Integration

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
        password: '$2b$10$hewTMmw3Y2UaZYLdW6Z2v.7jYXt20XouMG5ogc/rqBGOXHFKJhBh6', // Keep your existing hash
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
        accountId: process.env.VONAGE_ACCOUNT_ID || '4c42609f',
        baseUrl: 'https://rest.nexmo.com',
        apiBaseUrl: 'https://api.nexmo.com'
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
    rates: {},
    customerMappings: [] // Store Vonage sub-account to Xero customer mappings
};

// =================== HELPER FUNCTIONS ===================

function getCountryFromNumber(phoneNumber) {
    if (!phoneNumber) return 'Unknown';
    
    const cleaned = phoneNumber.replace(/[^\d]/g, '');
    
    if (cleaned.startsWith('61')) return 'AU';
    if (cleaned.startsWith('1')) return 'US';
    if (cleaned.startsWith('44')) return 'UK';
    if (cleaned.startsWith('65')) return 'SG';
    if (cleaned.startsWith('64')) return 'NZ';
    if (cleaned.startsWith('86')) return 'CN';
    if (cleaned.startsWith('91')) return 'IN';
    
    return 'Other';
}

function getCountryName(code) {
    const countries = {
        'AU': 'Australia',
        'US': 'United States',
        'UK': 'United Kingdom',
        'SG': 'Singapore',
        'NZ': 'New Zealand',
        'CN': 'China',
        'IN': 'India',
        'Other': 'Other Countries',
        'Unknown': 'Unknown'
    };
    return countries[code] || code;
}

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

// Test Vonage connection
app.get('/api/vonage/test', authenticateToken, async (req, res) => {
    try {
        if (!config.vonage.apiKey || !config.vonage.apiSecret) {
            return res.json({ 
                success: false, 
                error: 'Vonage API credentials not configured' 
            });
        }
        
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        // Get account balance to test connection
        const response = await axios.get(`${config.vonage.baseUrl}/account/get-balance`, {
            headers: {
                'Authorization': `Basic ${auth}`
            }
        });
        
        res.json({ 
            success: true, 
            message: 'Vonage connected successfully',
            balance: response.data.value,
            autoReload: response.data.autoReload
        });
        
    } catch (error) {
        console.error('Vonage test error:', error.response?.data || error.message);
        res.json({ 
            success: false, 
            error: error.response?.data || error.message 
        });
    }
});

// Test Reports API v2 access
app.get('/api/vonage/test-reports', authenticateToken, async (req, res) => {
    try {
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        // Try to get just 1 record to test API access
        const response = await axios.get(`${config.vonage.apiBaseUrl}/v2/reports/records`, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json'
            },
            params: {
                account_id: config.vonage.accountId,
                product: 'SMS',
                date_start: '2025-09-01T00:00:00Z',
                date_end: '2025-09-23T23:59:59Z',
                limit: 1
            }
        });
        
        res.json({ 
            success: true, 
            message: 'Reports API v2 is working!',
            sample: response.data
        });
        
    } catch (error) {
        if (error.response?.status === 404) {
            res.json({ 
                success: false, 
                error: '404 - Reports API v2 endpoint not found',
                solution: 'Please contact Vonage support to enable Reports API v2 for account ' + config.vonage.accountId
            });
        } else if (error.response?.status === 401) {
            res.json({ 
                success: false, 
                error: '401 - Authentication failed',
                solution: 'Check your API credentials'
            });
        } else {
            res.json({ 
                success: false, 
                error: error.response?.data || error.message,
                status: error.response?.status
            });
        }
    }
});

// =================== VONAGE RESELLER API ENDPOINTS ===================

// Get all sub-accounts under your master account
app.get('/api/vonage/subaccounts', authenticateToken, async (req, res) => {
    try {
        if (!config.vonage.apiKey || !config.vonage.apiSecret) {
            return res.json({ success: false, error: 'Vonage not configured' });
        }
        
        const response = await axios.get(`${config.vonage.baseUrl}/accounts/${config.vonage.accountId}/subaccounts`, {
            params: {
                api_key: config.vonage.apiKey,
                api_secret: config.vonage.apiSecret
            }
        });
        
        res.json({ 
            success: true, 
            data: response.data._embedded?.primary_accounts || []
        });
        
    } catch (error) {
        console.error('Vonage subaccounts error:', error.response?.data || error.message);
        res.json({ 
            success: false, 
            error: error.response?.data?.error_text || error.message 
        });
    }
});

// Create a new sub-account
app.post('/api/vonage/subaccounts/create', authenticateToken, async (req, res) => {
    try {
        const { name, secret, use_primary_account_balance } = req.body;
        
        const response = await axios.post(`${config.vonage.baseUrl}/accounts/${config.vonage.accountId}/subaccounts`, {
            name: name,
            secret: secret || undefined,
            use_primary_account_balance: use_primary_account_balance || true
        }, {
            params: {
                api_key: config.vonage.apiKey,
                api_secret: config.vonage.apiSecret
            }
        });
        
        res.json({ 
            success: true, 
            data: response.data 
        });
        
    } catch (error) {
        console.error('Create subaccount error:', error.response?.data || error.message);
        res.json({ 
            success: false, 
            error: error.response?.data?.error_text || error.message 
        });
    }
});

// Get sub-account details
app.get('/api/vonage/subaccounts/:subAccountId', authenticateToken, async (req, res) => {
    try {
        const { subAccountId } = req.params;
        
        const response = await axios.get(`${config.vonage.baseUrl}/accounts/${config.vonage.accountId}/subaccounts/${subAccountId}`, {
            params: {
                api_key: config.vonage.apiKey,
                api_secret: config.vonage.apiSecret
            }
        });
        
        res.json({ 
            success: true, 
            data: response.data 
        });
        
    } catch (error) {
        res.json({ 
            success: false, 
            error: error.response?.data?.error_text || error.message 
        });
    }
});

// Update sub-account
app.patch('/api/vonage/subaccounts/:subAccountId', authenticateToken, async (req, res) => {
    try {
        const { subAccountId } = req.params;
        const { suspended, use_primary_account_balance, name } = req.body;
        
        const response = await axios.patch(`${config.vonage.baseUrl}/accounts/${config.vonage.accountId}/subaccounts/${subAccountId}`, {
            suspended: suspended,
            use_primary_account_balance: use_primary_account_balance,
            name: name
        }, {
            params: {
                api_key: config.vonage.apiKey,
                api_secret: config.vonage.apiSecret
            }
        });
        
        res.json({ 
            success: true, 
            data: response.data 
        });
        
    } catch (error) {
        res.json({ 
            success: false, 
            error: error.response?.data?.error_text || error.message 
        });
    }
});

// Transfer credit between accounts
app.post('/api/vonage/credit-transfer', authenticateToken, async (req, res) => {
    try {
        const { from, to, amount, reference } = req.body;
        
        const response = await axios.post(`${config.vonage.baseUrl}/accounts/${config.vonage.accountId}/credit-transfers`, {
            from: from,
            to: to,
            amount: amount,
            reference: reference || 'Credit transfer'
        }, {
            params: {
                api_key: config.vonage.apiKey,
                api_secret: config.vonage.apiSecret
            }
        });
        
        res.json({ 
            success: true, 
            data: response.data 
        });
        
    } catch (error) {
        res.json({ 
            success: false, 
            error: error.response?.data?.error_text || error.message 
        });
    }
});

// Get balance transfers history
app.get('/api/vonage/balance-transfers', authenticateToken, async (req, res) => {
    try {
        const { start_date, end_date, subaccount } = req.query;
        
        const response = await axios.get(`${config.vonage.baseUrl}/accounts/${config.vonage.accountId}/balance-transfers`, {
            params: {
                api_key: config.vonage.apiKey,
                api_secret: config.vonage.apiSecret,
                start_date: start_date,
                end_date: end_date,
                subaccount: subaccount
            }
        });
        
        res.json({ 
            success: true, 
            data: response.data 
        });
        
    } catch (error) {
        res.json({ 
            success: false, 
            error: error.response?.data?.error_text || error.message 
        });
    }
});

// =================== SMS USAGE ENDPOINTS ===================

// Get SMS usage for all sub-accounts (FIXED VERSION)
app.get('/api/vonage/usage/sms', authenticateToken, async (req, res) => {
    try {
        const { month = new Date().toISOString().slice(0, 7) } = req.query;
        
        if (!config.vonage.apiKey || !config.vonage.apiSecret) {
            return res.json({ 
                success: false, 
                error: 'Vonage not configured' 
            });
        }
        
        // Calculate date range for the month
        const startDate = `${month}-01T00:00:00Z`;
        const endDate = new Date(month + '-01');
        endDate.setMonth(endDate.getMonth() + 1);
        endDate.setDate(0); // Last day of month
        const endDateStr = `${endDate.toISOString().slice(0, 10)}T23:59:59Z`;
        
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        // Get SMS records using Reports API v2
        const response = await axios.get(`${config.vonage.apiBaseUrl}/v2/reports/records`, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json'
            },
            params: {
                account_id: config.vonage.accountId,
                product: 'SMS',
                direction: 'outbound',
                date_start: startDate,
                date_end: endDateStr,
                include_subaccounts: true // This is crucial for seeing sub-account data
            }
        });
        
        // Process the SMS records
        const records = response.data.records || [];
        const usage = {
            total: records.length,
            outbound: 0,
            inbound: 0,
            byCountry: {},
            bySubAccount: {}
        };
        
        // Group by country and sub-account
        records.forEach(record => {
            // Count by direction
            if (record.direction === 'outbound') usage.outbound++;
            if (record.direction === 'inbound') usage.inbound++;
            
            // Group by country
            const country = record.to_country || getCountryFromNumber(record.to);
            const countryName = getCountryName(country);
            
            if (!usage.byCountry[countryName]) {
                usage.byCountry[countryName] = {
                    code: country,
                    name: countryName,
                    count: 0,
                    cost: 0
                };
            }
            usage.byCountry[countryName].count++;
            usage.byCountry[countryName].cost += parseFloat(record.price || 0);
            
            // Group by sub-account
            const subAccount = record.account_id || 'master';
            if (!usage.bySubAccount[subAccount]) {
                usage.bySubAccount[subAccount] = {
                    accountId: subAccount,
                    count: 0,
                    cost: 0,
                    byCountry: {}
                };
            }
            usage.bySubAccount[subAccount].count++;
            usage.bySubAccount[subAccount].cost += parseFloat(record.price || 0);
            
            // Add country breakdown per sub-account
            if (!usage.bySubAccount[subAccount].byCountry[countryName]) {
                usage.bySubAccount[subAccount].byCountry[countryName] = {
                    code: country,
                    name: countryName,
                    count: 0,
                    cost: 0
                };
            }
            usage.bySubAccount[subAccount].byCountry[countryName].count++;
            usage.bySubAccount[subAccount].byCountry[countryName].cost += parseFloat(record.price || 0);
        });
        
        res.json({ 
            success: true, 
            data: usage,
            month: month,
            recordCount: records.length
        });
        
    } catch (error) {
        console.error('SMS usage error:', error.response?.data || error.message);
        
        // Check if it's a 404 - Reports API might not be enabled
        if (error.response?.status === 404) {
            res.json({ 
                success: false, 
                error: 'Reports API v2 not available. Please ensure it\'s enabled in your Vonage account.',
                instructions: 'Contact Vonage support to enable Reports API v2 for your account.'
            });
        } else {
            res.json({ 
                success: false, 
                error: error.response?.data?.error_text || error.message 
            });
        }
    }
});

// Get SMS usage for specific sub-account/customer
app.get('/api/vonage/subaccounts/:subAccountId/sms-usage', authenticateToken, async (req, res) => {
    try {
        const { subAccountId } = req.params;
        const { startDate, endDate } = req.query;
        
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        const response = await axios.get(`${config.vonage.apiBaseUrl}/v2/reports/records`, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json'
            },
            params: {
                account_id: subAccountId,
                product: 'SMS',
                date_start: startDate || `${new Date().toISOString().slice(0, 7)}-01T00:00:00Z`,
                date_end: endDate || new Date().toISOString()
            }
        });
        
        // Process and group by country
        const records = response.data.records || [];
        const byCountry = {};
        let totalCost = 0;
        
        records.forEach(record => {
            const country = record.to_country || getCountryFromNumber(record.to);
            const countryName = getCountryName(country);
            
            if (!byCountry[countryName]) {
                byCountry[countryName] = {
                    code: country,
                    name: countryName,
                    count: 0,
                    cost: 0
                };
            }
            byCountry[countryName].count++;
            byCountry[countryName].cost += parseFloat(record.price || 0);
            totalCost += parseFloat(record.price || 0);
        });
        
        res.json({ 
            success: true, 
            data: {
                subAccountId,
                totalSMS: records.length,
                totalCost: totalCost,
                byCountry,
                period: {
                    start: startDate || `${new Date().toISOString().slice(0, 7)}-01`,
                    end: endDate || new Date().toISOString().slice(0, 10)
                }
            }
        });
        
    } catch (error) {
        console.error('Sub-account SMS usage error:', error.response?.data || error.message);
        res.json({ 
            success: false, 
            error: error.response?.data?.error_text || error.message 
        });
    }
});

// Get 6-month SMS history for a specific sub-account
app.get('/api/vonage/subaccounts/:subAccountId/sms-history', authenticateToken, async (req, res) => {
    try {
        const { subAccountId } = req.params;
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        // Get last 6 months
        const months = [];
        const date = new Date();
        for (let i = 0; i < 6; i++) {
            months.push(date.toISOString().slice(0, 7));
            date.setMonth(date.getMonth() - 1);
        }
        
        const history = await Promise.all(
            months.map(async (month) => {
                try {
                    const startDate = `${month}-01T00:00:00Z`;
                    const endDate = new Date(month + '-01');
                    endDate.setMonth(endDate.getMonth() + 1);
                    endDate.setDate(0);
                    const endDateStr = `${endDate.toISOString().slice(0, 10)}T23:59:59Z`;
                    
                    const response = await axios.get(`${config.vonage.apiBaseUrl}/v2/reports/records`, {
                        headers: {
                            'Authorization': `Basic ${auth}`,
                            'Content-Type': 'application/json'
                        },
                        params: {
                            account_id: subAccountId,
                            product: 'SMS',
                            date_start: startDate,
                            date_end: endDateStr
                        }
                    });
                    
                    const records = response.data.records || [];
                    const byCountry = {};
                    let totalCost = 0;
                    
                    records.forEach(record => {
                        const country = record.to_country || getCountryFromNumber(record.to);
                        const countryName = getCountryName(country);
                        
                        if (!byCountry[countryName]) {
                            byCountry[countryName] = {
                                count: 0,
                                cost: 0
                            };
                        }
                        byCountry[countryName].count++;
                        byCountry[countryName].cost += parseFloat(record.price || 0);
                        totalCost += parseFloat(record.price || 0);
                    });
                    
                    return {
                        month: month,
                        totalSMS: records.length,
                        totalCost: totalCost,
                        byCountry: byCountry
                    };
                } catch (error) {
                    return {
                        month: month,
                        totalSMS: 0,
                        totalCost: 0,
                        byCountry: {},
                        error: 'Failed to fetch data'
                    };
                }
            })
        );
        
        res.json({
            success: true,
            data: {
                subAccountId: subAccountId,
                history: history
            }
        });
        
    } catch (error) {
        console.error('SMS history error:', error.response?.data || error.message);
        res.json({ 
            success: false, 
            error: error.response?.data?.error_text || error.message 
        });
    }
});

// =================== CUSTOMER MAPPING ENDPOINTS ===================

// Link Vonage sub-account to Xero customer
app.post('/api/customers/map', authenticateToken, async (req, res) => {
    try {
        const { vonageSubAccountId, xeroContactId, customerName } = req.body;
        
        // Check if mapping already exists
        const existingMapping = dataStore.customerMappings.find(
            m => m.vonageSubAccountId === vonageSubAccountId || m.xeroContactId === xeroContactId
        );
        
        if (existingMapping) {
            return res.json({
                success: false,
                error: 'Mapping already exists for this sub-account or Xero contact'
            });
        }
        
        // Create new mapping
        const newMapping = {
            id: Date.now(),
            vonageSubAccountId,
            xeroContactId,
            customerName,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        
        dataStore.customerMappings.push(newMapping);
        
        res.json({
            success: true,
            data: newMapping
        });
        
    } catch (error) {
        console.error('Customer mapping error:', error);
        res.json({
            success: false,
            error: error.message
        });
    }
});

// Get all customer mappings
app.get('/api/customers/mappings', authenticateToken, async (req, res) => {
    try {
        res.json({
            success: true,
            data: dataStore.customerMappings
        });
    } catch (error) {
        res.json({
            success: false,
            error: error.message
        });
    }
});

// Get customer SMS usage with Xero mapping
app.get('/api/customers/:customerId/sms-usage', authenticateToken, async (req, res) => {
    try {
        const { customerId } = req.params;
        const { month = new Date().toISOString().slice(0, 7) } = req.query;
        
        // Find customer mapping
        const mapping = dataStore.customerMappings.find(m => m.id == customerId);
        if (!mapping) {
            return res.json({
                success: false,
                error: 'Customer mapping not found'
            });
        }
        
        // Get SMS usage for the sub-account
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        const startDate = `${month}-01T00:00:00Z`;
        const endDate = new Date(month + '-01');
        endDate.setMonth(endDate.getMonth() + 1);
        endDate.setDate(0);
        const endDateStr = `${endDate.toISOString().slice(0, 10)}T23:59:59Z`;
        
        const response = await axios.get(`${config.vonage.apiBaseUrl}/v2/reports/records`, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json'
            },
            params: {
                account_id: mapping.vonageSubAccountId,
                product: 'SMS',
                date_start: startDate,
                date_end: endDateStr
            }
        });
        
        const records = response.data.records || [];
        const byCountry = {};
        let totalCost = 0;
        
        records.forEach(record => {
            const country = record.to_country || getCountryFromNumber(record.to);
            const countryName = getCountryName(country);
            
            if (!byCountry[countryName]) {
                byCountry[countryName] = {
                    code: country,
                    name: countryName,
                    count: 0,
                    cost: 0
                };
            }
            byCountry[countryName].count++;
            byCountry[countryName].cost += parseFloat(record.price || 0);
            totalCost += parseFloat(record.price || 0);
        });
        
        res.json({
            success: true,
            data: {
                customer: mapping,
                usage: {
                    month: month,
                    totalSMS: records.length,
                    totalCost: totalCost,
                    byCountry: byCountry
                }
            }
        });
        
    } catch (error) {
        console.error('Customer SMS usage error:', error.response?.data || error.message);
        res.json({
            success: false,
            error: error.response?.data?.error_text || error.message
        });
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
            { id: 'XERO-DEF456', name: 'TechStart Inc', email: 'billing@techstart.com' },
            { id: 'XERO-GHI789', name: 'Global Services Ltd', email: 'finance@globalservices.com' },
            { id: 'XERO-JKL012', name: 'Digital Solutions', email: 'accounts@digitalsolutions.com' }
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
        console.warn('Set VONAGE_API_KEY, VONAGE_API_SECRET, and VONAGE_ACCOUNT_ID in environment variables.');
    } else {
        console.log('✅ Vonage API credentials configured');
        console.log('   Account ID: ' + config.vonage.accountId);
    }
    if (!process.env.XERO_CLIENT_ID) {
        console.warn('⚠️  WARNING: Xero API credentials not set.');
    }
});