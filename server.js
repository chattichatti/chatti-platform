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
            return res.json({ 
                success: false, 
                error: 'Vonage credentials not configured'
            });
        }
        
        console.log('Fetching sub-accounts for master account:', config.vonage.accountId);
        
        // Use the Subaccounts API with master credentials
        const response = await axios.get(`https://api.vonage.com/accounts/subaccounts`, {
            params: {
                api_key: config.vonage.apiKey,
                api_secret: config.vonage.apiSecret
            }
        });
        
        console.log('Sub-accounts response:', response.data);
        
        // The response contains _embedded.primary_accounts array
        const subAccounts = response.data._embedded?.primary_accounts || [];
        
        res.json({ 
            success: true, 
            data: subAccounts,
            count: subAccounts.length
        });
        
    } catch (error) {
        console.error('Vonage subaccounts error:', error.response?.status, error.response?.data);
        res.json({ 
            success: false, 
            error: error.response?.data?.title || error.response?.data?.detail || error.message 
        });
    }
});

// Get specific sub-account details
app.get('/api/vonage/subaccounts/:subAccountKey', authenticateToken, async (req, res) => {
    try {
        const { subAccountKey } = req.params;
        
        const response = await axios.get(`https://api.vonage.com/accounts/subaccounts/${subAccountKey}`, {
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
            error: error.response?.data?.detail || error.message 
        });
    }
});

// Create a new sub-account
app.post('/api/vonage/subaccounts', authenticateToken, async (req, res) => {
    try {
        const { name, secret, use_primary_account_balance = true } = req.body;
        
        const requestData = {
            name: name,
            use_primary_account_balance: use_primary_account_balance
        };
        
        // Only add secret if provided
        if (secret) {
            requestData.secret = secret;
        }
        
        const response = await axios.post('https://api.vonage.com/accounts/subaccounts', 
            requestData,
            {
                params: {
                    api_key: config.vonage.apiKey,
                    api_secret: config.vonage.apiSecret
                }
            }
        );
        
        res.json({ 
            success: true, 
            data: response.data 
        });
        
    } catch (error) {
        console.error('Create subaccount error:', error.response?.data);
        res.json({ 
            success: false, 
            error: error.response?.data?.detail || error.message 
        });
    }
});

// Update sub-account (suspend/unsuspend, modify settings)
app.patch('/api/vonage/subaccounts/:subAccountKey', authenticateToken, async (req, res) => {
    try {
        const { subAccountKey } = req.params;
        const updateData = req.body; // Can include: suspended, use_primary_account_balance, name
        
        const response = await axios.patch(`https://api.vonage.com/accounts/subaccounts/${subAccountKey}`,
            updateData,
            {
                params: {
                    api_key: config.vonage.apiKey,
                    api_secret: config.vonage.apiSecret
                }
            }
        );
        
        res.json({ 
            success: true, 
            data: response.data 
        });
        
    } catch (error) {
        res.json({ 
            success: false, 
            error: error.response?.data?.detail || error.message 
        });
    }
});

// Transfer balance to sub-account
app.post('/api/vonage/balance-transfers', authenticateToken, async (req, res) => {
    try {
        const { from, to, amount, reference } = req.body;
        
        const response = await axios.post('https://api.vonage.com/accounts/balance-transfers',
            {
                from: from || config.vonage.accountId, // Default from master
                to: to,
                amount: parseFloat(amount),
                reference: reference || 'Balance transfer'
            },
            {
                params: {
                    api_key: config.vonage.apiKey,
                    api_secret: config.vonage.apiSecret
                }
            }
        );
        
        res.json({ 
            success: true, 
            data: response.data 
        });
        
    } catch (error) {
        res.json({ 
            success: false, 
            error: error.response?.data?.detail || error.message 
        });
    }
});

// Get balance transfer history
app.get('/api/vonage/balance-transfers', authenticateToken, async (req, res) => {
    try {
        const { start_date, end_date, subaccount } = req.query;
        
        const params = {
            api_key: config.vonage.apiKey,
            api_secret: config.vonage.apiSecret
        };
        
        if (start_date) params.start_date = start_date;
        if (end_date) params.end_date = end_date;
        if (subaccount) params.subaccount = subaccount;
        
        const response = await axios.get('https://api.vonage.com/accounts/balance-transfers', {
            params: params
        });
        
        res.json({ 
            success: true, 
            data: response.data._embedded?.balance_transfers || []
        });
        
    } catch (error) {
        res.json({ 
            success: false, 
            error: error.response?.data?.detail || error.message 
        });
    }
});

// =================== SMS USAGE ENDPOINTS - USING REPORTS API ===================

// Get SMS usage for ALL sub-accounts using master credentials
app.get('/api/vonage/usage/sms', authenticateToken, async (req, res) => {
    try {
        const { month = new Date().toISOString().slice(0, 7) } = req.query;
        
        if (!config.vonage.apiKey || !config.vonage.apiSecret) {
            return res.json({ 
                success: false, 
                error: 'Vonage credentials not configured'
            });
        }
        
        // First, get all sub-accounts
        console.log('Fetching sub-accounts...');
        const subAccountsResponse = await axios.get('https://api.vonage.com/accounts/subaccounts', {
            params: {
                api_key: config.vonage.apiKey,
                api_secret: config.vonage.apiSecret
            }
        });
        
        const subAccounts = subAccountsResponse.data._embedded?.primary_accounts || [];
        console.log(`Found ${subAccounts.length} sub-accounts`);
        
        // Calculate date range for the month
        const year = parseInt(month.split('-')[0]);
        const monthNum = parseInt(month.split('-')[1]);
        const startDate = new Date(Date.UTC(year, monthNum - 1, 1));
        const endDate = new Date(Date.UTC(year, monthNum, 0, 23, 59, 59));
        
        const startDateStr = startDate.toISOString();
        const endDateStr = endDate.toISOString();
        
        console.log(`Fetching SMS data from ${startDateStr} to ${endDateStr}`);
        
        // Aggregate usage data
        const aggregatedUsage = {
            total: 0,
            outbound: 0,
            inbound: 0,
            byCountry: {},
            bySubAccount: {},
            totalCost: 0
        };
        
        // Use Reports API v2 with master credentials to get data for all sub-accounts
        try {
            const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
            
            // Get SMS records for the master account (includes all sub-accounts)
            const reportsResponse = await axios.get('https://api.nexmo.com/v2/reports/records', {
                headers: {
                    'Authorization': `Basic ${auth}`,
                    'Content-Type': 'application/json'
                },
                params: {
                    account_id: config.vonage.accountId,
                    product: 'SMS',
                    date_start: startDateStr,
                    date_end: endDateStr,
                    include_subaccounts: 'true',
                    status: 'delivered'  // Only count delivered messages
                }
            });
            
            console.log(`Found ${reportsResponse.data.records?.length || 0} SMS records`);
            
            const records = reportsResponse.data.records || [];
            
            // Process each record
            records.forEach(record => {
                aggregatedUsage.total++;
                
                // Count by direction
                if (record.direction === 'outbound') {
                    aggregatedUsage.outbound++;
                } else if (record.direction === 'inbound') {
                    aggregatedUsage.inbound++;
                }
                
                // Calculate cost
                const cost = parseFloat(record.price || 0);
                aggregatedUsage.totalCost += cost;
                
                // Group by country
                const country = record.to_country || getCountryFromNumber(record.to);
                const countryName = getCountryName(country);
                
                if (!aggregatedUsage.byCountry[countryName]) {
                    aggregatedUsage.byCountry[countryName] = {
                        code: country,
                        name: countryName,
                        count: 0,
                        cost: 0
                    };
                }
                aggregatedUsage.byCountry[countryName].count++;
                aggregatedUsage.byCountry[countryName].cost += cost;
                
                // Group by sub-account
                const accountId = record.account_id || 'master';
                const accountName = subAccounts.find(acc => acc.api_key === accountId)?.name || accountId;
                
                if (!aggregatedUsage.bySubAccount[accountId]) {
                    aggregatedUsage.bySubAccount[accountId] = {
                        accountId: accountId,
                        accountName: accountName,
                        count: 0,
                        cost: 0,
                        byCountry: {}
                    };
                }
                
                aggregatedUsage.bySubAccount[accountId].count++;
                aggregatedUsage.bySubAccount[accountId].cost += cost;
                
                // Add country breakdown per sub-account
                if (!aggregatedUsage.bySubAccount[accountId].byCountry[countryName]) {
                    aggregatedUsage.bySubAccount[accountId].byCountry[countryName] = {
                        code: country,
                        name: countryName,
                        count: 0,
                        cost: 0
                    };
                }
                aggregatedUsage.bySubAccount[accountId].byCountry[countryName].count++;
                aggregatedUsage.bySubAccount[accountId].byCountry[countryName].cost += cost;
            });
            
            res.json({ 
                success: true, 
                data: aggregatedUsage,
                month: month,
                recordCount: records.length,
                subAccountsCount: subAccounts.length
            });
            
        } catch (reportsError) {
            console.error('Reports API error:', reportsError.response?.status, reportsError.response?.data);
            
            // If Reports API fails, return error message
            res.json({ 
                success: false, 
                error: 'Reports API v2 error',
                details: reportsError.response?.data?.detail || reportsError.message,
                message: 'Please ensure Reports API v2 is enabled for your master account'
            });
        }
        
    } catch (error) {
        console.error('SMS usage error:', error.response?.status, error.response?.data);
        res.json({ 
            success: false, 
            error: error.response?.data?.detail || error.message 
        });
    }
});

// Get SMS usage for a specific sub-account
app.get('/api/vonage/subaccounts/:subAccountKey/sms-usage', authenticateToken, async (req, res) => {
    try {
        const { subAccountKey } = req.params;
        const { month = new Date().toISOString().slice(0, 7) } = req.query;
        
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        // Calculate date range
        const year = parseInt(month.split('-')[0]);
        const monthNum = parseInt(month.split('-')[1]);
        const startDate = new Date(Date.UTC(year, monthNum - 1, 1));
        const endDate = new Date(Date.UTC(year, monthNum, 0, 23, 59, 59));
        
        const response = await axios.get('https://api.nexmo.com/v2/reports/records', {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json'
            },
            params: {
                account_id: subAccountKey,
                product: 'SMS',
                date_start: startDate.toISOString(),
                date_end: endDate.toISOString(),
                status: 'delivered'
            }
        });
        
        // Process records
        const records = response.data.records || [];
        const usage = {
            subAccountKey: subAccountKey,
            month: month,
            total: records.length,
            totalCost: 0,
            byCountry: {}
        };
        
        records.forEach(record => {
            const cost = parseFloat(record.price || 0);
            usage.totalCost += cost;
            
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
            usage.byCountry[countryName].cost += cost;
        });
        
        res.json({ 
            success: true, 
            data: usage
        });
        
    } catch (error) {
        console.error('Sub-account SMS usage error:', error.response?.data);
        res.json({ 
            success: false, 
            error: error.response?.data?.detail || error.message 
        });
    }
});

// Get 6-month SMS history for a specific sub-account
app.get('/api/vonage/subaccounts/:subAccountKey/sms-history', authenticateToken, async (req, res) => {
    try {
        const { subAccountKey } = req.params;
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        // Get last 6 months
        const history = [];
        const today = new Date();
        
        for (let i = 0; i < 6; i++) {
            const date = new Date(today.getFullYear(), today.getMonth() - i, 1);
            const year = date.getFullYear();
            const month = date.getMonth();
            
            const startDate = new Date(Date.UTC(year, month, 1));
            const endDate = new Date(Date.UTC(year, month + 1, 0, 23, 59, 59));
            
            try {
                const response = await axios.get('https://api.nexmo.com/v2/reports/records', {
                    headers: {
                        'Authorization': `Basic ${auth}`,
                        'Content-Type': 'application/json'
                    },
                    params: {
                        account_id: subAccountKey,
                        product: 'SMS',
                        date_start: startDate.toISOString(),
                        date_end: endDate.toISOString(),
                        status: 'delivered'
                    }
                });
                
                const records = response.data.records || [];
                let totalCost = 0;
                const byCountry = {};
                
                records.forEach(record => {
                    const cost = parseFloat(record.price || 0);
                    totalCost += cost;
                    
                    const country = record.to_country || getCountryFromNumber(record.to);
                    const countryName = getCountryName(country);
                    
                    if (!byCountry[countryName]) {
                        byCountry[countryName] = {
                            count: 0,
                            cost: 0
                        };
                    }
                    byCountry[countryName].count++;
                    byCountry[countryName].cost += cost;
                });
                
                history.push({
                    month: `${year}-${String(month + 1).padStart(2, '0')}`,
                    totalSMS: records.length,
                    totalCost: totalCost,
                    byCountry: byCountry
                });
                
            } catch (error) {
                history.push({
                    month: `${year}-${String(month + 1).padStart(2, '0')}`,
                    totalSMS: 0,
                    totalCost: 0,
                    byCountry: {},
                    error: 'Failed to fetch data'
                });
            }
        }
        
        res.json({
            success: true,
            data: {
                subAccountKey: subAccountKey,
                history: history
            }
        });
        
    } catch (error) {
        console.error('SMS history error:', error.response?.data);
        res.json({ 
            success: false, 
            error: error.response?.data?.detail || error.message 
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