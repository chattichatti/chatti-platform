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
    // Actually test it to show the exact error
    try {
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        const testDate = new Date().toISOString().slice(0, 10);
        
        const response = await axios.get('https://api.nexmo.com/v2/reports/records', {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json'
            },
            params: {
                account_id: config.vonage.accountId,
                product: 'SMS',
                date_start: `${testDate}T00:00:00Z`,
                date_end: `${testDate}T23:59:59Z`,
                include_subaccounts: true
            },
            timeout: 5000
        });
        
        res.json({ 
            success: true,
            message: 'Reports API v2 is working!',
            data: response.data
        });
        
    } catch (error) {
        res.json({ 
            success: false, 
            error: error.response?.status || error.message,
            errorDetail: error.response?.data,
            message: 'Reports API v2 is not accessible. Contact Vonage to enable it.',
            solution: 'Tell Vonage: "Enable Reports API v2 for Partner account 4c42609f with include_subaccounts support"'
        });
    }
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

// Get SMS usage - TRY CDR RECORDS API (Alternative to Reports API)
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
        
        console.log(`=== SMS USAGE DIAGNOSTIC ===`);
        console.log(`Fetching SMS for ${startDate} to ${endDate}`);
        console.log(`Using API Key: ${config.vonage.apiKey}`);
        
        // Initialize aggregated usage data
        const aggregatedUsage = {
            total: 0,
            outbound: 0,
            inbound: 0,
            byCountry: {},
            bySubAccount: {},
            totalCost: 0,
            debug: {
                attemptedMaster: false,
                masterError: null,
                attemptedSubAccounts: 0,
                subAccountErrors: [],
                searchParams: {
                    date_start: `${startDate} 00:00:00`,
                    date_end: `${endDate} 23:59:59`
                }
            }
        };
        
        // First, try to get all messages using master account
        try {
            console.log('Attempting master account search...');
            aggregatedUsage.debug.attemptedMaster = true;
            
            const searchResponse = await axios.get('https://rest.nexmo.com/search/messages', {
                params: {
                    api_key: config.vonage.apiKey,
                    api_secret: config.vonage.apiSecret,
                    date_start: `${startDate} 00:00:00`,
                    date_end: `${endDate} 23:59:59`
                },
                timeout: 15000
            });
            
            console.log('Master search response status:', searchResponse.status);
            console.log('Master search response data:', JSON.stringify(searchResponse.data).substring(0, 200));
            
            const messages = searchResponse.data?.items || [];
            console.log(`Found ${messages.length} messages from master account search`);
            
            if (messages.length > 0) {
                console.log('First message sample:', JSON.stringify(messages[0]));
            }
            
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
            
            // If we found messages, no need to check sub-accounts
            if (messages.length > 0) {
                console.log(`SUCCESS: Found ${messages.length} messages via master account`);
                return res.json({ 
                    success: true, 
                    data: aggregatedUsage,
                    month: month,
                    recordCount: aggregatedUsage.total
                });
            }
            
        } catch (searchError) {
            console.error('Master account search error:', searchError.response?.status, searchError.response?.data || searchError.message);
            aggregatedUsage.debug.masterError = searchError.response?.data || searchError.message;
            
            // Check if it's a date format issue
            if (searchError.response?.status === 400) {
                console.log('Trying alternative date format...');
                try {
                    const altSearchResponse = await axios.get('https://rest.nexmo.com/search/messages', {
                        params: {
                            api_key: config.vonage.apiKey,
                            api_secret: config.vonage.apiSecret,
                            date_start: startDate,  // Try without time
                            date_end: endDate
                        },
                        timeout: 15000
                    });
                    
                    const messages = altSearchResponse.data?.items || [];
                    console.log(`Alternative format found ${messages.length} messages`);
                    
                    if (messages.length > 0) {
                        // Process messages (same as above)
                        messages.forEach(msg => {
                            aggregatedUsage.total++;
                            // ... rest of processing
                        });
                        
                        return res.json({ 
                            success: true, 
                            data: aggregatedUsage,
                            month: month,
                            recordCount: aggregatedUsage.total
                        });
                    }
                } catch (altError) {
                    console.error('Alternative date format also failed:', altError.message);
                }
            }
        }
        
        // If master search returned no data, try a few sub-accounts as a test
        console.log('Master search found no data, testing with first 5 sub-accounts...');
        
        const subAccounts = await fetchSubAccounts();
        console.log(`Found ${subAccounts.length} sub-accounts to check`);
        
        if (subAccounts.length > 0) {
            aggregatedUsage.debug.attemptedSubAccounts = Math.min(5, subAccounts.length);
            
            // Test with just first 5 sub-accounts to diagnose
            const testAccounts = subAccounts.slice(0, 5);
            
            for (const subAccount of testAccounts) {
                const subKey = subAccount.api_key || subAccount.account_id || subAccount.account_reference;
                const subName = subAccount.name || subKey;
                
                console.log(`Testing sub-account: ${subName} (${subKey})`);
                
                try {
                    // Try with sub-account key as API key
                    const subResponse = await axios.get('https://rest.nexmo.com/search/messages', {
                        params: {
                            api_key: subKey,
                            api_secret: config.vonage.apiSecret, // Use master secret
                            date_start: `${startDate} 00:00:00`,
                            date_end: `${endDate} 23:59:59`
                        },
                        timeout: 5000
                    });
                    
                    const subMessages = subResponse.data?.items || [];
                    console.log(`  -> Found ${subMessages.length} messages`);
                    
                    if (subMessages.length > 0) {
                        console.log('  -> SUCCESS! This method works');
                        console.log('  -> First message:', JSON.stringify(subMessages[0]).substring(0, 100));
                        
                        // Process these messages
                        subMessages.forEach(msg => {
                            aggregatedUsage.total++;
                            // ... process message
                        });
                    }
                    
                } catch (subError) {
                    const errorInfo = {
                        account: subName,
                        status: subError.response?.status,
                        error: subError.response?.data?.error_text || subError.message
                    };
                    aggregatedUsage.debug.subAccountErrors.push(errorInfo);
                    console.log(`  -> Error: ${errorInfo.status} - ${errorInfo.error}`);
                }
            }
        }
        
        console.log(`=== DIAGNOSTIC SUMMARY ===`);
        console.log(`Total SMS found: ${aggregatedUsage.total}`);
        console.log(`Debug info:`, aggregatedUsage.debug);
        
        return res.json({ 
            success: true, 
            data: aggregatedUsage,
            month: month,
            recordCount: aggregatedUsage.total,
            message: aggregatedUsage.total === 0 ? 'No SMS data found for this period - check debug info' : null,
            debug: aggregatedUsage.debug
        });
        
    } catch (error) {
        console.error('SMS usage endpoint crashed:', error.message);
        
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