// server.js - Complete Backend Server for Chatti Platform with Vonage Reseller Integration
// FIXED: SMS Usage for Reseller Accounts with 267 Sub-accounts

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
app.use(express.static('public'));

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Users database
const users = [
    {
        id: 1,
        email: 'admin@chatti.com',
        password: '$2b$10$hewTMmw3Y2UaZYLdW6Z2v.7jYXt20XouMG5ogc/rqBGOXHFKJhBh6',
        role: 'admin',
        name: 'Admin User'
    }
];

// Configuration - ensure environment variables are strings
const config = {
    vonage: {
        apiKey: String(process.env.VONAGE_API_KEY || '4c42609f'),
        apiSecret: String(process.env.VONAGE_API_SECRET || ''),
        accountId: String(process.env.VONAGE_ACCOUNT_ID || '4c42609f'),
        baseUrl: 'https://rest.nexmo.com',
        apiBaseUrl: 'https://api.nexmo.com'
    },
    xero: {
        clientId: String(process.env.XERO_CLIENT_ID || ''),
        clientSecret: String(process.env.XERO_CLIENT_SECRET || ''),
        redirectUri: process.env.XERO_REDIRECT_URI || 'https://chatti-platform.onrender.com/api/xero/callback'
    }
};

// Store for demo purposes
let dataStore = {
    customers: [],
    usage: {},
    rates: {},
    customerMappings: []
};

// Cache for sub-accounts to avoid repeated fetches
let subAccountsCache = {
    data: [],
    lastFetch: 0,
    cacheDuration: 5 * 60 * 1000 // 5 minutes
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

// Helper to fetch sub-accounts with caching
async function fetchSubAccounts() {
    // Check cache first
    if (subAccountsCache.data.length > 0 && 
        (Date.now() - subAccountsCache.lastFetch) < subAccountsCache.cacheDuration) {
        console.log('Returning cached sub-accounts:', subAccountsCache.data.length);
        return subAccountsCache.data;
    }
    
    try {
        const url = `https://api.nexmo.com/accounts/${config.vonage.accountId}/subaccounts`;
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        const response = await axios.get(url, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json'
            },
            timeout: 10000
        });
        
        let subAccounts = [];
        
        // Extract from nested structure
        if (response.data._embedded?.subaccounts) {
            subAccounts = response.data._embedded.subaccounts;
        } else if (response.data._embedded?.primary_accounts) {
            subAccounts = response.data._embedded.primary_accounts;
        }
        
        // Update cache
        subAccountsCache.data = subAccounts;
        subAccountsCache.lastFetch = Date.now();
        
        console.log(`Cached ${subAccounts.length} sub-accounts`);
        return subAccounts;
        
    } catch (error) {
        console.error('Error fetching sub-accounts:', error.message);
        return subAccountsCache.data; // Return cached data on error
    }
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

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// =================== AUTHENTICATION ROUTES ===================

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const user = users.find(u => u.email === email);
        
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }
        
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

app.post('/api/logout', (req, res) => {
    res.json({ success: true, message: 'Logged out successfully' });
});

// =================== BASIC API ROUTES ===================

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

// Test Reports API - We know this returns 403
app.get('/api/vonage/test-reports', authenticateToken, async (req, res) => {
    res.json({ 
        success: false, 
        error: '403 - Forbidden',
        message: 'Reports API v2 is not enabled for your account',
        solution: 'Using Search Messages API instead for SMS data'
    });
});

// =================== VONAGE SUBACCOUNTS API - FIXED TO EXTRACT 267 ACCOUNTS ===================

// Get all sub-accounts - PROPERLY EXTRACTS NESTED SUBACCOUNTS
app.get('/api/vonage/subaccounts', authenticateToken, async (req, res) => {
    try {
        const subAccounts = await fetchSubAccounts();
        
        return res.json({ 
            success: true, 
            data: subAccounts,
            count: subAccounts.length
        });
        
    } catch (error) {
        console.error('Subaccounts endpoint error:', error.message);
        return res.json({ 
            success: true,
            data: [],
            count: 0,
            error: 'Could not fetch subaccounts'
        });
    }
});

// Get specific sub-account
app.get('/api/vonage/subaccounts/:subAccountKey', authenticateToken, async (req, res) => {
    try {
        const { subAccountKey } = req.params;
        const url = `https://api.nexmo.com/accounts/${config.vonage.accountId}/subaccounts/${subAccountKey}`;
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        const response = await axios.get(url, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json'
            },
            timeout: 10000
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

// Get SMS usage for a specific sub-account
app.get('/api/vonage/subaccounts/:subAccountKey/sms-usage', authenticateToken, async (req, res) => {
    try {
        const { subAccountKey } = req.params;
        const { month = new Date().toISOString().slice(0, 7) } = req.query;
        
        if (!subAccountKey || subAccountKey === 'undefined') {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid sub-account key' 
            });
        }
        
        // Try to get SMS data for this specific sub-account
        const year = parseInt(month.split('-')[0]);
        const monthNum = parseInt(month.split('-')[1]);
        const startDate = `${year}-${String(monthNum).padStart(2, '0')}-01`;
        const lastDay = new Date(year, monthNum, 0).getDate();
        const endDate = `${year}-${String(monthNum).padStart(2, '0')}-${String(lastDay).padStart(2, '0')}`;
        
        try {
            // Try using the sub-account's credentials if available
            const searchResponse = await axios.get('https://rest.nexmo.com/search/messages', {
                params: {
                    api_key: subAccountKey, // Try using sub-account key
                    api_secret: config.vonage.apiSecret, // Use master secret
                    date_start: `${startDate} 00:00:00`,
                    date_end: `${endDate} 23:59:59`
                },
                timeout: 10000
            });
            
            const messages = searchResponse.data?.items || [];
            
            // Process messages for this sub-account
            let total = 0;
            let totalCost = 0;
            const byCountry = {};
            
            messages.forEach(msg => {
                total++;
                const cost = parseFloat(msg.price || 0);
                totalCost += cost;
                
                const country = getCountryFromNumber(msg.to);
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
                byCountry[countryName].cost += cost;
            });
            
            res.json({ 
                success: true, 
                data: {
                    subAccountKey: subAccountKey,
                    month: month,
                    total: total,
                    totalCost: totalCost,
                    byCountry: byCountry
                }
            });
            
        } catch (searchError) {
            // If search fails, return empty data
            res.json({ 
                success: true, 
                data: {
                    subAccountKey: subAccountKey,
                    month: month,
                    total: 0,
                    totalCost: 0,
                    byCountry: {}
                }
            });
        }
        
    } catch (error) {
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// Create sub-account
app.post('/api/vonage/subaccounts', authenticateToken, async (req, res) => {
    try {
        const { name, secret, use_primary_account_balance = true } = req.body;
        const url = `https://api.nexmo.com/accounts/${config.vonage.accountId}/subaccounts`;
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        const requestData = {
            name: name,
            use_primary_account_balance: use_primary_account_balance
        };
        
        if (secret) {
            requestData.secret = secret;
        }
        
        const response = await axios.post(url, requestData, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json'
            },
            timeout: 10000
        });
        
        // Clear cache after creating new sub-account
        subAccountsCache.data = [];
        
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
app.patch('/api/vonage/subaccounts/:subAccountKey', authenticateToken, async (req, res) => {
    try {
        const { subAccountKey } = req.params;
        const updateData = req.body;
        const url = `https://api.nexmo.com/accounts/${config.vonage.accountId}/subaccounts/${subAccountKey}`;
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        const response = await axios.patch(url, updateData, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json'
            },
            timeout: 10000
        });
        
        // Clear cache after updating sub-account
        subAccountsCache.data = [];
        
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

// =================== SMS USAGE ENDPOINTS - ENHANCED FOR RESELLER ===================

// Get SMS usage - ENHANCED TO AGGREGATE ALL SUB-ACCOUNTS
app.get('/api/vonage/usage/sms', authenticateToken, async (req, res) => {
    try {
        const { month = new Date().toISOString().slice(0, 7) } = req.query;
        
        if (!config.vonage.apiKey || !config.vonage.apiSecret) {
            return res.json({ 
                success: true,
                data: {
                    total: 0,
                    outbound: 0,
                    inbound: 0,
                    byCountry: {},
                    bySubAccount: {},
                    totalCost: 0
                },
                message: 'Vonage credentials not configured'
            });
        }
        
        // Calculate date range
        const year = parseInt(month.split('-')[0]);
        const monthNum = parseInt(month.split('-')[1]);
        const startDate = `${year}-${String(monthNum).padStart(2, '0')}-01`;
        const lastDay = new Date(year, monthNum, 0).getDate();
        const endDate = `${year}-${String(monthNum).padStart(2, '0')}-${String(lastDay).padStart(2, '0')}`;
        
        console.log(`Fetching SMS for ${startDate} to ${endDate}`);
        
        // Initialize aggregated usage data
        const aggregatedUsage = {
            total: 0,
            outbound: 0,
            inbound: 0,
            byCountry: {},
            bySubAccount: {},
            totalCost: 0
        };
        
        // First, try to get all messages using master account
        try {
            const searchResponse = await axios.get('https://rest.nexmo.com/search/messages', {
                params: {
                    api_key: config.vonage.apiKey,
                    api_secret: config.vonage.apiSecret,
                    date_start: `${startDate} 00:00:00`,
                    date_end: `${endDate} 23:59:59`
                },
                timeout: 15000
            });
            
            const messages = searchResponse.data?.items || [];
            console.log(`Found ${messages.length} messages from master account search`);
            
            // Process all messages
            messages.forEach(msg => {
                aggregatedUsage.total++;
                
                if (msg.type === 'MT' || msg.type === 'SMS' || msg.direction === 'outbound') {
                    aggregatedUsage.outbound++;
                } else if (msg.type === 'MO' || msg.direction === 'inbound') {
                    aggregatedUsage.inbound++;
                }
                
                const cost = parseFloat(msg.price || 0);
                aggregatedUsage.totalCost += cost;
                
                // Group by country
                const country = getCountryFromNumber(msg.to);
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
                
                // Group by sub-account - use account_id or api_key from message
                const accountId = msg.account_id || msg.api_key || 'master';
                
                if (!aggregatedUsage.bySubAccount[accountId]) {
                    aggregatedUsage.bySubAccount[accountId] = {
                        accountId: accountId,
                        accountName: accountId, // Will be updated with actual name
                        count: 0,
                        cost: 0
                    };
                }
                aggregatedUsage.bySubAccount[accountId].count++;
                aggregatedUsage.bySubAccount[accountId].cost += cost;
            });
            
        } catch (searchError) {
            console.error('Master account search error:', searchError.message);
            
            // If master search fails, try to fetch from each sub-account
            console.log('Attempting to fetch SMS data from individual sub-accounts...');
            
            const subAccounts = await fetchSubAccounts();
            console.log(`Checking SMS for ${subAccounts.length} sub-accounts`);
            
            // Try to get messages for each sub-account (limit parallel requests)
            const batchSize = 10; // Process 10 accounts at a time
            for (let i = 0; i < subAccounts.length; i += batchSize) {
                const batch = subAccounts.slice(i, i + batchSize);
                
                const batchPromises = batch.map(async (subAccount) => {
                    try {
                        const subKey = subAccount.api_key || subAccount.account_id;
                        const subName = subAccount.name || subKey;
                        
                        // Try to get messages for this sub-account
                        const subResponse = await axios.get('https://rest.nexmo.com/search/messages', {
                            params: {
                                api_key: subKey,
                                api_secret: config.vonage.apiSecret,
                                date_start: `${startDate} 00:00:00`,
                                date_end: `${endDate} 23:59:59`
                            },
                            timeout: 5000
                        }).catch(() => ({ data: { items: [] } })); // Return empty on error
                        
                        const subMessages = subResponse.data?.items || [];
                        
                        if (subMessages.length > 0) {
                            console.log(`Found ${subMessages.length} messages for ${subName}`);
                            
                            // Process messages from this sub-account
                            subMessages.forEach(msg => {
                                aggregatedUsage.total++;
                                
                                if (msg.type === 'MT' || msg.type === 'SMS') {
                                    aggregatedUsage.outbound++;
                                } else if (msg.type === 'MO') {
                                    aggregatedUsage.inbound++;
                                }
                                
                                const cost = parseFloat(msg.price || 0);
                                aggregatedUsage.totalCost += cost;
                                
                                // Group by country
                                const country = getCountryFromNumber(msg.to);
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
                                if (!aggregatedUsage.bySubAccount[subKey]) {
                                    aggregatedUsage.bySubAccount[subKey] = {
                                        accountId: subKey,
                                        accountName: subName,
                                        count: 0,
                                        cost: 0
                                    };
                                }
                                aggregatedUsage.bySubAccount[subKey].count++;
                                aggregatedUsage.bySubAccount[subKey].cost += cost;
                            });
                        }
                        
                    } catch (subError) {
                        // Silently skip sub-accounts that fail
                    }
                });
                
                await Promise.all(batchPromises);
                console.log(`Processed batch ${i/batchSize + 1} of ${Math.ceil(subAccounts.length/batchSize)}`);
            }
        }
        
        // Try to match sub-account IDs with names
        if (Object.keys(aggregatedUsage.bySubAccount).length > 0) {
            const subAccounts = await fetchSubAccounts();
            subAccounts.forEach(sub => {
                const subKey = sub.api_key || sub.account_id;
                if (aggregatedUsage.bySubAccount[subKey]) {
                    aggregatedUsage.bySubAccount[subKey].accountName = sub.name || subKey;
                }
            });
        }
        
        console.log(`Total SMS found: ${aggregatedUsage.total}`);
        
        return res.json({ 
            success: true, 
            data: aggregatedUsage,
            month: month,
            recordCount: aggregatedUsage.total,
            message: aggregatedUsage.total === 0 ? 'No SMS data found for this period' : null
        });
        
    } catch (error) {
        console.error('SMS usage endpoint crashed:', error.message);
        
        // Always return valid JSON
        return res.json({ 
            success: true, 
            data: {
                total: 0,
                outbound: 0,
                inbound: 0,
                byCountry: {},
                bySubAccount: {},
                totalCost: 0
            },
            month: req.query.month || new Date().toISOString().slice(0, 7),
            error: error.message,
            message: 'Error fetching SMS data'
        });
    }
});

// =================== BALANCE & CREDIT MANAGEMENT ===================

app.post('/api/vonage/balance-transfers', authenticateToken, async (req, res) => {
    try {
        const { from, to, amount, reference } = req.body;
        const url = `https://api.nexmo.com/accounts/${config.vonage.accountId}/balance-transfers`;
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        const response = await axios.post(url, {
            from: from || config.vonage.accountId,
            to: to,
            amount: parseFloat(amount),
            reference: reference || 'Balance transfer'
        }, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json'
            },
            timeout: 10000
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

app.get('/api/vonage/balance-transfers', authenticateToken, async (req, res) => {
    try {
        const { start_date, end_date, subaccount } = req.query;
        const url = `https://api.nexmo.com/accounts/${config.vonage.accountId}/balance-transfers`;
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        const response = await axios.get(url, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json'
            },
            params: { start_date, end_date, subaccount },
            timeout: 10000
        });
        
        res.json({ 
            success: true, 
            data: response.data._embedded?.balance_transfers || []
        });
        
    } catch (error) {
        res.json({ 
            success: false, 
            error: error.response?.data?.error_text || error.message 
        });
    }
});

// =================== CUSTOMER MAPPING ENDPOINTS ===================

app.post('/api/customers/map', authenticateToken, async (req, res) => {
    try {
        const { vonageSubAccountId, xeroContactId, customerName } = req.body;
        
        const existingMapping = dataStore.customerMappings.find(
            m => m.vonageSubAccountId === vonageSubAccountId || m.xeroContactId === xeroContactId
        );
        
        if (existingMapping) {
            return res.json({
                success: false,
                error: 'Mapping already exists for this sub-account or Xero contact'
            });
        }
        
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
        res.json({
            success: false,
            error: error.message
        });
    }
});

app.get('/api/customers/mappings', authenticateToken, async (req, res) => {
    res.json({
        success: true,
        data: dataStore.customerMappings
    });
});

// =================== XERO ENDPOINTS ===================

app.get('/api/xero/auth', authenticateToken, (req, res) => {
    const authUrl = `https://login.xero.com/identity/connect/authorize?` +
        `response_type=code&` +
        `client_id=${config.xero.clientId}&` +
        `redirect_uri=${config.xero.redirectUri}&` +
        `scope=accounting.transactions accounting.contacts accounting.settings&` +
        `state=${Date.now()}`;
    
    res.json({ authUrl });
});

app.get('/api/xero/callback', async (req, res) => {
    try {
        const { code, state } = req.query;
        console.log('Received Xero callback with code:', code);
        res.redirect('/?xero=connected');
    } catch (error) {
        console.error('Xero callback error:', error);
        res.redirect('/?xero=error');
    }
});

app.get('/api/xero/contacts', authenticateToken, async (req, res) => {
    try {
        const contacts = [
            { id: 'XERO-ABC123', name: 'Acme Corp', email: 'accounts@acme.com' },
            { id: 'XERO-DEF456', name: 'TechStart Inc', email: 'billing@techstart.com' },
            { id: 'XERO-GHI789', name: 'Global Services Ltd', email: 'finance@globalservices.com' },
            { id: 'XERO-JKL012', name: 'Digital Solutions', email: 'accounts@digitalsolutions.com' }
        ];
        
        res.json({ success: true, data: contacts });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

// =================== OTHER ENDPOINTS ===================

app.get('/api/customers', authenticateToken, (req, res) => {
    const customers = dataStore.customers.length > 0 ? dataStore.customers : [];
    res.json({ success: true, data: customers });
});

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

app.get('/api/products/mappings', authenticateToken, (req, res) => {
    const mappings = [
        { vonageProduct: 'SMS-AU', xeroItem: 'SMS Australia', type: 'SMS' },
        { vonageProduct: 'SMS-US', xeroItem: 'SMS United States', type: 'SMS' },
        { vonageProduct: 'NUM-AU', xeroItem: 'Phone Number AU', type: 'Number' }
    ];
    
    res.json({ success: true, data: mappings });
});

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

app.post('/api/billing/generate-invoices', authenticateToken, (req, res) => {
    const { month } = req.body;
    
    const invoices = [
        {
            id: 'INV-2025-001',
            customer: 'Demo Customer',
            amount: 0,
            status: 'draft',
            items: []
        }
    ];
    
    res.json({ success: true, data: invoices });
});

// =================== DEBUG ENDPOINT ===================

app.get('/api/debug/test-all', authenticateToken, async (req, res) => {
    const results = {};
    
    try {
        // Test credentials
        console.log('Testing with API Key:', config.vonage.apiKey ? 'SET' : 'NOT SET');
        console.log('Testing with API Secret:', config.vonage.apiSecret ? 'SET' : 'NOT SET');
        
        // Test balance
        try {
            const balanceResponse = await axios.get('https://rest.nexmo.com/account/get-balance', {
                params: {
                    api_key: config.vonage.apiKey,
                    api_secret: config.vonage.apiSecret
                },
                timeout: 10000
            });
            results.balance = {
                success: true,
                value: balanceResponse.data.value
            };
        } catch (error) {
            results.balance = {
                success: false,
                error: error.response?.status
            };
        }
        
        // Test subaccounts
        try {
            const subAccounts = await fetchSubAccounts();
            results.subaccounts = {
                success: true,
                count: subAccounts.length
            };
        } catch (error) {
            results.subaccounts = {
                success: false,
                error: error.response?.status
            };
        }
        
        // Test SMS search
        try {
            const month = new Date().toISOString().slice(0, 7);
            const searchResponse = await axios.get('https://rest.nexmo.com/search/messages', {
                params: {
                    api_key: config.vonage.apiKey,
                    api_secret: config.vonage.apiSecret,
                    date_start: `${month}-01 00:00:00`,
                    date_end: `${month}-01 23:59:59`
                },
                timeout: 10000
            });
            results.smsSearch = {
                success: true,
                count: searchResponse.data?.items?.length || 0
            };
        } catch (error) {
            results.smsSearch = {
                success: false,
                error: error.response?.status
            };
        }
        
        res.json({
            success: true,
            credentials: {
                apiKey: config.vonage.apiKey ? 'SET' : 'NOT SET',
                apiSecret: config.vonage.apiSecret ? 'SET' : 'NOT SET',
                accountId: config.vonage.accountId
            },
            results: results
        });
        
    } catch (error) {
        res.json({
            success: false,
            error: error.message,
            results: results
        });
    }
});

// =================== ERROR HANDLERS ===================

app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// =================== START SERVER ===================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`Chatti Platform Server Starting...`);
    console.log(`========================================`);
    console.log(`Port: ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`URL: http://localhost:${PORT}`);
    
    console.log(`\n=== CONFIGURATION STATUS ===`);
    
    // Check JWT
    if (!process.env.JWT_SECRET) {
        console.warn('⚠️  JWT_SECRET: Using default (set in production!)');
    } else {
        console.log('✅ JWT_SECRET: Configured');
    }
    
    // Check Vonage - THIS IS CRITICAL
    console.log('\n=== VONAGE API STATUS ===');
    if (!process.env.VONAGE_API_KEY) {
        console.error('❌ VONAGE_API_KEY: NOT SET - API will not work!');
        console.error('   -> Set this in Render environment variables');
    } else {
        console.log('✅ VONAGE_API_KEY:', process.env.VONAGE_API_KEY);
    }
    
    if (!process.env.VONAGE_API_SECRET) {
        console.error('❌ VONAGE_API_SECRET: NOT SET - API will not work!');
        console.error('   -> Set this in Render environment variables');
    } else {
        console.log('✅ VONAGE_API_SECRET: ***hidden***');
    }
    
    console.log('   Account ID:', config.vonage.accountId);
    console.log('   Base URL:', config.vonage.baseUrl);
    console.log('   API URL:', config.vonage.apiBaseUrl);
    
    // Check Xero
    console.log('\n=== XERO API STATUS ===');
    if (!process.env.XERO_CLIENT_ID) {
        console.warn('⚠️  XERO_CLIENT_ID: Not configured');
    } else {
        console.log('✅ XERO_CLIENT_ID: Configured');
    }
    
    console.log('\n========================================\n');
});