// server.js - Complete Backend Server for Chatti Platform with Vonage Reseller Integration
// Version: Fixed date format for Reports API

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

// Test Reports API
app.get('/api/vonage/test-reports', authenticateToken, async (req, res) => {
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
                date_start: testDate,
                date_end: testDate
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
            message: 'Reports API v2 test failed',
            solution: 'Contact Vonage support if this persists'
        });
    }
});

// =================== VONAGE SUBACCOUNTS API ===================

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
        
        // For now, return empty data since individual sub-account access requires their API secret
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

// =================== SMS USAGE - FIXED DATE FORMAT ===================

// Get SMS usage - FIXED FOR RESELLER ACCOUNTS WITH PROPER DATE FORMAT
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
        
        // Calculate date range - SIMPLE FORMAT
        const year = parseInt(month.split('-')[0]);
        const monthNum = parseInt(month.split('-')[1]);
        const startDate = `${year}-${String(monthNum).padStart(2, '0')}-01`;
        const lastDay = new Date(year, monthNum, 0).getDate();
        const endDate = `${year}-${String(monthNum).padStart(2, '0')}-${String(lastDay).padStart(2, '0')}`;
        
        console.log(`\n=== SMS USAGE REQUEST ===`);
        console.log(`Month: ${month}`);
        console.log(`Date range: ${startDate} to ${endDate} (YYYY-MM-DD format)`);
        console.log(`Account ID: ${config.vonage.accountId}`);
        
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        // Initialize aggregated usage data
        const aggregatedUsage = {
            total: 0,
            outbound: 0,
            inbound: 0,
            byCountry: {},
            bySubAccount: {},
            totalCost: 0
        };
        
        // Debug info
        const debugInfo = {
            attemptedSync: false,
            syncError: null,
            attemptedAsync: false,
            asyncError: null
        };
        
        // METHOD 1: Try ASYNCHRONOUS method FIRST (required for sub-accounts)
        console.log('\n1. Trying ASYNCHRONOUS Reports API (required for sub-accounts)...');
        debugInfo.attemptedAsync = true;
        
        try {
            const asyncUrl = 'https://api.nexmo.com/v2/reports';
            const asyncBody = {
                product: 'SMS',
                account_id: config.vonage.accountId,
                include_subaccounts: true,  // This ONLY works with async
                date_start: startDate,      // Simple YYYY-MM-DD format
                date_end: endDate           // Simple YYYY-MM-DD format
            };
            
            console.log('Async URL:', asyncUrl);
            console.log('Async body:', JSON.stringify(asyncBody, null, 2));
            
            const createReportResponse = await axios.post(asyncUrl, asyncBody, {
                headers: {
                    'Authorization': `Basic ${auth}`,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                timeout: 10000
            });
            
            console.log('Async report creation response:', createReportResponse.status);
            console.log('Response data:', createReportResponse.data);
            
            const reportRequestId = createReportResponse.data?.request_id || createReportResponse.data?.id;
            
            if (reportRequestId) {
                console.log('Report request created with ID:', reportRequestId);
                
                // Wait for report to be ready
                let reportReady = false;
                let attempts = 0;
                const maxAttempts = 15;  // Increase max attempts
                let reportData = null;
                
                while (!reportReady && attempts < maxAttempts) {
                    attempts++;
                    
                    // Wait progressively longer between checks
                    const waitTime = Math.min(3000 + (attempts * 1000), 10000);
                    console.log(`Waiting ${waitTime}ms before checking report status (attempt ${attempts})...`);
                    await new Promise(resolve => setTimeout(resolve, waitTime));
                    
                    try {
                        const statusUrl = `https://api.nexmo.com/v2/reports/${reportRequestId}`;
                        console.log(`Checking report status at: ${statusUrl}`);
                        
                        const statusResponse = await axios.get(statusUrl, {
                            headers: {
                                'Authorization': `Basic ${auth}`,
                                'Accept': 'application/json'
                            },
                            timeout: 10000
                        });
                        
                        const status = statusResponse.data?.status || statusResponse.data?.report_status;
                        console.log(`Report status: ${status}`);
                        
                        if (status === 'completed' || status === 'complete' || status === 'SUCCESS' || status === 'COMPLETED') {
                            reportReady = true;
                            
                            // Check different possible data locations
                            reportData = statusResponse.data?.items || 
                                        statusResponse.data?.records || 
                                        statusResponse.data?._embedded?.records ||
                                        statusResponse.data?.data;
                            
                            if (!reportData && statusResponse.data?.download_url) {
                                console.log('Downloading report from:', statusResponse.data.download_url);
                                const downloadResponse = await axios.get(statusResponse.data.download_url, {
                                    headers: { 'Authorization': `Basic ${auth}` },
                                    timeout: 30000
                                });
                                reportData = downloadResponse.data?.items || 
                                           downloadResponse.data?.records || 
                                           downloadResponse.data;
                            }
                            
                            if (!reportData && statusResponse.data?._links?.download?.href) {
                                const downloadUrl = statusResponse.data._links.download.href;
                                console.log('Downloading from _links:', downloadUrl);
                                const downloadResponse = await axios.get(downloadUrl, {
                                    headers: { 'Authorization': `Basic ${auth}` },
                                    timeout: 30000
                                });
                                reportData = downloadResponse.data?.items || 
                                           downloadResponse.data?.records || 
                                           downloadResponse.data;
                            }
                        } else if (status === 'failed' || status === 'error' || status === 'FAILED') {
                            throw new Error(`Report generation failed with status: ${status}`);
                        }
                        
                    } catch (statusError) {
                        console.error(`Error checking report status:`, statusError.message);
                        if (attempts >= maxAttempts) throw statusError;
                    }
                }
                
                if (reportData && Array.isArray(reportData) && reportData.length > 0) {
                    console.log(`SUCCESS! Processing ${reportData.length} records from async report`);
                    
                    // Process the report data
                    reportData.forEach(record => {
                        aggregatedUsage.total++;
                        
                        if (record.direction === 'outbound' || record.type === 'MT' || record.type === 'SMS') {
                            aggregatedUsage.outbound++;
                        } else if (record.direction === 'inbound' || record.type === 'MO') {
                            aggregatedUsage.inbound++;
                        }
                        
                        const cost = parseFloat(record.price || record.total_price || 0);
                        aggregatedUsage.totalCost += cost;
                        
                        const country = record.to_country || record.country || getCountryFromNumber(record.to);
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
                        
                        const accountId = record.account_id || record.from || 'master';
                        const accountName = record.account_name || accountId;
                        
                        if (!aggregatedUsage.bySubAccount[accountId]) {
                            aggregatedUsage.bySubAccount[accountId] = {
                                accountId: accountId,
                                accountName: accountName,
                                count: 0,
                                cost: 0
                            };
                        }
                        aggregatedUsage.bySubAccount[accountId].count++;
                        aggregatedUsage.bySubAccount[accountId].cost += cost;
                    });
                    
                    console.log('SUCCESS: Async Reports API with sub-accounts worked!');
                    return res.json({ 
                        success: true, 
                        data: aggregatedUsage,
                        month: month,
                        recordCount: aggregatedUsage.total,
                        method: 'asynchronous'
                    });
                }
            }
            
        } catch (asyncError) {
            console.error('Async method failed:', asyncError.response?.status);
            console.error('Error details:', asyncError.response?.data);
            debugInfo.asyncError = {
                status: asyncError.response?.status,
                data: asyncError.response?.data,
                message: asyncError.message
            };
        }
        
        // METHOD 2: Try SYNCHRONOUS as fallback (won't include sub-accounts)
        console.log('\n2. Trying SYNCHRONOUS Reports API (master account only)...');
        debugInfo.attemptedSync = true;
        
        try {
            const syncUrl = 'https://api.nexmo.com/v2/reports/records';
            
            // DON'T use include_subaccounts - it's not supported with sync
            // Use simple date format
            const syncParams = {
                account_id: config.vonage.accountId,
                product: 'SMS',
                date_start: startDate,  // Simple YYYY-MM-DD format
                date_end: endDate       // Simple YYYY-MM-DD format
            };
            
            console.log('Sync URL:', syncUrl);
            console.log('Sync params (no include_subaccounts):', JSON.stringify(syncParams, null, 2));
            
            const syncResponse = await axios.get(syncUrl, {
                headers: {
                    'Authorization': `Basic ${auth}`,
                    'Accept': 'application/json'
                },
                params: syncParams,
                timeout: 30000
            });
            
            console.log('Sync response status:', syncResponse.status);
            
            const records = syncResponse.data?.records || syncResponse.data?._embedded?.records || [];
            console.log(`Synchronous method returned ${records.length} records (master account only)`);
            
            if (records.length > 0) {
                // Process records
                records.forEach(record => {
                    aggregatedUsage.total++;
                    
                    if (record.direction === 'outbound' || record.type === 'MT') {
                        aggregatedUsage.outbound++;
                    } else if (record.direction === 'inbound' || record.type === 'MO') {
                        aggregatedUsage.inbound++;
                    }
                    
                    const cost = parseFloat(record.price || record.total_price || 0);
                    aggregatedUsage.totalCost += cost;
                    
                    const country = record.to_country || record.country || getCountryFromNumber(record.to);
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
                    
                    const accountId = record.account_id || 'master';
                    if (!aggregatedUsage.bySubAccount[accountId]) {
                        aggregatedUsage.bySubAccount[accountId] = {
                            accountId: accountId,
                            accountName: 'Master Account',
                            count: 0,
                            cost: 0
                        };
                    }
                    aggregatedUsage.bySubAccount[accountId].count++;
                    aggregatedUsage.bySubAccount[accountId].cost += cost;
                });
                
                console.log('SUCCESS: Synchronous Reports API worked (master account only)!');
                return res.json({ 
                    success: true, 
                    data: aggregatedUsage,
                    month: month,
                    recordCount: aggregatedUsage.total,
                    method: 'synchronous',
                    note: 'Only master account data - use async for sub-accounts'
                });
            }
            
        } catch (syncError) {
            console.error('Synchronous method failed:', syncError.response?.status);
            console.error('Error details:', syncError.response?.data);
            debugInfo.syncError = {
                status: syncError.response?.status,
                data: syncError.response?.data
            };
        }
        
        console.log('\n=== BOTH METHODS FAILED ===');
        console.log('Debug info:', JSON.stringify(debugInfo, null, 2));
        
        return res.json({ 
            success: true, 
            data: aggregatedUsage,
            month: month,
            recordCount: 0,
            message: 'No SMS data found. Check if there is SMS activity in this period.',
            debug: debugInfo
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
    
    // Check Vonage
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