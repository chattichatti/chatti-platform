// server.js - Complete Backend Server for Chatti Platform with Vonage Reseller Integration
// Version: Optimized for scale - millions of SMS across 267 sub-accounts

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

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

// Configuration
const config = {
    vonage: {
        apiKey: String(process.env.VONAGE_API_KEY || '4c42609f'),
        apiSecret: String(process.env.VONAGE_API_SECRET || ''),
        accountId: String(process.env.VONAGE_ACCOUNT_ID || '4c42609f'),
        applicationId: String(process.env.VONAGE_APPLICATION_ID || ''),
        privateKey: process.env.VONAGE_PRIVATE_KEY || '',
        baseUrl: 'https://rest.nexmo.com',
        apiBaseUrl: 'https://api.nexmo.com'
    },
    xero: {
        clientId: String(process.env.XERO_CLIENT_ID || ''),
        clientSecret: String(process.env.XERO_CLIENT_SECRET || ''),
        redirectUri: process.env.XERO_REDIRECT_URI || 'https://chatti-platform.onrender.com/api/xero/callback'
    }
};

// Store for data
let dataStore = {
    customers: [],
    usage: {},
    rates: {},
    customerMappings: [],
    smsCache: {}
};

// Cache for sub-accounts
let subAccountsCache = {
    data: [],
    lastFetch: 0,
    cacheDuration: 5 * 60 * 1000
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
        
        if (response.data._embedded?.subaccounts) {
            subAccounts = response.data._embedded.subaccounts;
        } else if (response.data._embedded?.primary_accounts) {
            subAccounts = response.data._embedded.primary_accounts;
        }
        
        subAccountsCache.data = subAccounts;
        subAccountsCache.lastFetch = Date.now();
        
        console.log(`Cached ${subAccounts.length} sub-accounts`);
        return subAccounts;
        
    } catch (error) {
        console.error('Error fetching sub-accounts:', error.message);
        return subAccountsCache.data;
    }
}

// =================== JWT GENERATION FOR VONAGE ===================

function generateVonageJWT() {
    if (!config.vonage.applicationId || !config.vonage.privateKey) {
        console.log('No Vonage Application configured, using Basic Auth');
        return null;
    }
    
    try {
        const now = Math.floor(Date.now() / 1000);
        const payload = {
            application_id: config.vonage.applicationId,
            iat: now,
            jti: uuidv4(),
            exp: now + 3600
        };
        
        const token = jwt.sign(payload, config.vonage.privateKey, {
            algorithm: 'RS256'
        });
        
        return token;
    } catch (error) {
        console.error('Error generating Vonage JWT:', error.message);
        return null;
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

// Test JWT authentication for Reports API
app.get('/api/vonage/test-jwt', authenticateToken, async (req, res) => {
    try {
        const jwtToken = generateVonageJWT();
        
        if (!jwtToken) {
            return res.json({
                success: false,
                message: 'JWT generation failed. Need VONAGE_APPLICATION_ID and VONAGE_PRIVATE_KEY',
                help: 'Create a Vonage Application and add credentials to Render'
            });
        }
        
        const testBody = {
            product: 'SMS',
            date_start: '2024-10-01T00:00:00Z',
            date_end: '2024-10-31T23:59:59Z',
            include_subaccounts: true,
            direction: 'outbound'
        };
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', testBody, {
            headers: {
                'Authorization': `Bearer ${jwtToken}`,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            timeout: 10000
        });
        
        res.json({
            success: true,
            message: 'JWT authentication working!',
            recordCount: response.data?.records?.length || 0,
            data: response.data
        });
        
    } catch (error) {
        res.json({
            success: false,
            error: error.response?.status,
            message: error.response?.data || error.message,
            help: 'Check that your Vonage Application has Reports API permissions'
        });
    }
});

// =================== VONAGE SUBACCOUNTS API ===================

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

// =================== SMS USAGE - OPTIMIZED FOR SCALE ===================

// Helper function to create and poll async report
async function fetchSMSDataAsync(headers, dateStart, dateEnd) {
    try {
        console.log('\nCreating ASYNC report...');
        
        // Step 1: Create async report request
        const createReportBody = {
            product: 'SMS',
            date_start: `${dateStart}T00:00:00Z`,
            date_end: `${dateEnd}T23:59:59Z`,
            include_subaccounts: true,
            direction: 'outbound'
        };
        
        console.log('Creating async report with body:', JSON.stringify(createReportBody, null, 2));
        
        // POST to /v2/reports/async for true async
        const createResponse = await axios.post('https://api.nexmo.com/v2/reports/async', createReportBody, {
            headers: headers,
            timeout: 30000
        });
        
        const reportId = createResponse.data?.request_id || createResponse.data?.id;
        
        if (!reportId) {
            console.log('No report ID returned from async request');
            return null;
        }
        
        console.log('Async report created with ID:', reportId);
        
        // Step 2: Poll for report completion
        let attempts = 0;
        const maxAttempts = 60; // 60 attempts * 5 seconds = 5 minutes max
        
        while (attempts < maxAttempts) {
            attempts++;
            
            // Wait before checking (longer for async reports)
            await new Promise(resolve => setTimeout(resolve, 5000));
            
            try {
                const statusUrl = `https://api.nexmo.com/v2/reports/async/${reportId}`;
                console.log(`Checking report status (attempt ${attempts})...`);
                
                const statusResponse = await axios.get(statusUrl, {
                    headers: headers,
                    timeout: 10000
                });
                
                const status = statusResponse.data?.status || statusResponse.data?.state;
                console.log(`Report status: ${status}`);
                
                if (status === 'completed' || status === 'COMPLETED') {
                    // Download the report
                    if (statusResponse.data?.download_url) {
                        console.log('Downloading report from:', statusResponse.data.download_url);
                        const downloadResponse = await axios.get(statusResponse.data.download_url, {
                            headers: headers,
                            timeout: 60000 // Large reports need more time
                        });
                        
                        const records = downloadResponse.data?.records || 
                                       downloadResponse.data?.items || 
                                       downloadResponse.data;
                        
                        console.log(`Async report returned ${records.length} records`);
                        return records;
                    }
                }
                
                if (status === 'failed' || status === 'FAILED') {
                    console.log('Report generation failed');
                    return null;
                }
                
            } catch (pollError) {
                console.error('Error polling report:', pollError.message);
            }
        }
        
        console.log('Report polling timed out');
        return null;
        
    } catch (error) {
        console.error('Async report error:', error.response?.status, error.message);
        if (error.response?.data) {
            console.error('Error details:', JSON.stringify(error.response.data, null, 2));
        }
        return null;
    }
}

// Alternative: Fetch data per sub-account (synchronous)
async function fetchSMSDataPerAccount(headers, dateStart, dateEnd, subAccounts) {
    console.log(`\nFetching SMS data for ${subAccounts.length} sub-accounts...`);
    let allRecords = [];
    
    // Always include master account
    const accountsToFetch = [
        { api_key: config.vonage.accountId, name: 'Master Account' },
        ...subAccounts
    ];
    
    for (let i = 0; i < accountsToFetch.length; i++) {
        const account = accountsToFetch[i];
        console.log(`Fetching account ${i + 1}/${accountsToFetch.length}: ${account.name}`);
        
        try {
            const requestBody = {
                product: 'SMS',
                account_id: account.api_key, // Specific account
                date_start: `${dateStart}T00:00:00Z`,
                date_end: `${dateEnd}T23:59:59Z`,
                direction: 'outbound'
            };
            
            const response = await axios.post('https://api.nexmo.com/v2/reports', requestBody, {
                headers: headers,
                timeout: 30000
            });
            
            const records = response.data?.records || [];
            
            if (records.length > 0) {
                // Add account info to each record
                records.forEach(record => {
                    record.account_id = account.api_key;
                    record.account_name = account.name;
                });
                
                allRecords = allRecords.concat(records);
                console.log(`  Found ${records.length} records for ${account.name}`);
            }
            
        } catch (error) {
            console.error(`  Error fetching ${account.name}:`, error.response?.status || error.message);
        }
        
        // Rate limiting - don't overwhelm the API
        if (i % 10 === 0 && i > 0) {
            console.log('Rate limiting pause...');
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    }
    
    console.log(`Total records across all accounts: ${allRecords.length}`);
    return allRecords;
}

// Process SMS records into aggregated data
function processRecords(records) {
    const aggregated = {
        total: 0,
        outbound: 0,
        inbound: 0,
        byCountry: {},
        bySubAccount: {},
        byDate: {},
        totalCost: 0
    };
    
    for (const record of records) {
        aggregated.total++;
        
        // Direction
        if (record.direction === 'outbound' || record.direction === 'out' || 
            record.type === 'MT' || record.type === 'SMS') {
            aggregated.outbound++;
        } else {
            aggregated.inbound++;
        }
        
        // Cost - try multiple field names
        const cost = parseFloat(
            record.price || 
            record.total_price || 
            record.cost || 
            record.charge || 
            record.amount || 
            record.rate ||
            0
        );
        
        if (cost === 0 && aggregated.total === 1) {
            console.log('Warning: Cost is 0. Available fields:', Object.keys(record));
        }
        
        aggregated.totalCost += cost;
        
        // Country
        const country = record.to_country || record.country || getCountryFromNumber(record.to || record.number);
        const countryName = getCountryName(country);
        
        if (!aggregated.byCountry[countryName]) {
            aggregated.byCountry[countryName] = {
                code: country,
                name: countryName,
                count: 0,
                cost: 0
            };
        }
        aggregated.byCountry[countryName].count++;
        aggregated.byCountry[countryName].cost += cost;
        
        // Sub-account
        const accountId = record.account_id || record.api_key || 'master';
        const accountName = record.account_name || accountId;
        
        if (!aggregated.bySubAccount[accountId]) {
            aggregated.bySubAccount[accountId] = {
                accountId: accountId,
                accountName: accountName,
                count: 0,
                cost: 0,
                byCountry: {},
                dailyTotals: {}
            };
        }
        aggregated.bySubAccount[accountId].count++;
        aggregated.bySubAccount[accountId].cost += cost;
        
        // Country per sub-account
        if (!aggregated.bySubAccount[accountId].byCountry[countryName]) {
            aggregated.bySubAccount[accountId].byCountry[countryName] = {
                count: 0,
                cost: 0
            };
        }
        aggregated.bySubAccount[accountId].byCountry[countryName].count++;
        aggregated.bySubAccount[accountId].byCountry[countryName].cost += cost;
        
        // Date tracking
        const messageDate = record.date_start || record.timestamp || record.created_at || record.date;
        if (messageDate) {
            const dateKey = messageDate.slice(0, 10);
            
            // Overall daily totals
            if (!aggregated.byDate[dateKey]) {
                aggregated.byDate[dateKey] = {
                    count: 0,
                    cost: 0
                };
            }
            aggregated.byDate[dateKey].count++;
            aggregated.byDate[dateKey].cost += cost;
            
            // Daily totals per account
            if (!aggregated.bySubAccount[accountId].dailyTotals[dateKey]) {
                aggregated.bySubAccount[accountId].dailyTotals[dateKey] = {
                    count: 0,
                    cost: 0
                };
            }
            aggregated.bySubAccount[accountId].dailyTotals[dateKey].count++;
            aggregated.bySubAccount[accountId].dailyTotals[dateKey].cost += cost;
        }
    }
    
    return aggregated;
}

// Get SMS usage for a specific month
app.get('/api/vonage/usage/sms', authenticateToken, async (req, res) => {
    try {
        const { month = new Date().toISOString().slice(0, 7), method = 'sync-per-account' } = req.query;
        
        // Check cache
        const cacheKey = `sms_${month}_${method}`;
        if (dataStore.smsCache[cacheKey] && 
            (Date.now() - dataStore.smsCache[cacheKey].timestamp) < 5 * 60 * 1000) {
            return res.json(dataStore.smsCache[cacheKey].data);
        }
        
        // Calculate date range
        const year = parseInt(month.split('-')[0]);
        const monthNum = parseInt(month.split('-')[1]);
        const dateStart = `${year}-${String(monthNum).padStart(2, '0')}-01`;
        const lastDay = new Date(year, monthNum, 0).getDate();
        const dateEnd = `${year}-${String(monthNum).padStart(2, '0')}-${String(lastDay).padStart(2, '0')}`;
        
        console.log(`\n=== SMS USAGE REQUEST ===`);
        console.log(`Month: ${month}`);
        console.log(`Date range: ${dateStart} to ${dateEnd}`);
        console.log(`Method: ${method}`);
        
        // Get JWT token
        const jwtToken = generateVonageJWT();
        const headers = jwtToken ? {
            'Authorization': `Bearer ${jwtToken}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        } : {
            'Authorization': `Basic ${Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64')}`,
            'Content-Type': 'application/json'
        };
        
        let records = [];
        
        // Choose method based on parameter
        if (method === 'async') {
            // Use true async method (creates report, requires polling)
            records = await fetchSMSDataAsync(headers, dateStart, dateEnd) || [];
        } else {
            // Default: Fetch per account (267 separate requests)
            const subAccounts = await fetchSubAccounts();
            records = await fetchSMSDataPerAccount(headers, dateStart, dateEnd, subAccounts) || [];
        }
        
        // Process records
        const aggregatedData = processRecords(records);
        
        const result = {
            success: true,
            data: aggregatedData,
            month: month,
            dateRange: `${dateStart} to ${dateEnd}`,
            recordCount: aggregatedData.total,
            accountCount: Object.keys(aggregatedData.bySubAccount).length,
            method: method
        };
        
        // Cache result
        dataStore.smsCache[cacheKey] = {
            data: result,
            timestamp: Date.now()
        };
        
        res.json(result);
        
    } catch (error) {
        console.error('SMS usage error:', error.message);
        res.json({
            success: false,
            error: error.message,
            data: {
                total: 0,
                outbound: 0,
                inbound: 0,
                byCountry: {},
                bySubAccount: {},
                byDate: {},
                totalCost: 0
            }
        });
    }
});

// Test async report creation
app.get('/api/vonage/test-async', authenticateToken, async (req, res) => {
    try {
        const jwtToken = generateVonageJWT();
        
        if (!jwtToken) {
            return res.json({
                success: false,
                message: 'JWT not configured'
            });
        }
        
        const headers = {
            'Authorization': `Bearer ${jwtToken}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        };
        
        // Create a small test report
        const testBody = {
            product: 'SMS',
            date_start: '2024-10-01T00:00:00Z',
            date_end: '2024-10-01T23:59:59Z', // Just one day for testing
            include_subaccounts: true,
            direction: 'outbound'
        };
        
        console.log('Creating test async report...');
        
        const response = await axios.post('https://api.nexmo.com/v2/reports/async', testBody, {
            headers: headers,
            timeout: 10000
        });
        
        res.json({
            success: true,
            message: 'Async report created',
            reportId: response.data?.request_id || response.data?.id,
            response: response.data
        });
        
    } catch (error) {
        res.json({
            success: false,
            error: error.response?.status,
            message: error.response?.data || error.message
        });
    }
});

// Get current month summary for dashboard (1-minute cache)
app.get('/api/vonage/dashboard/summary', authenticateToken, async (req, res) => {
    try {
        const currentMonth = new Date().toISOString().slice(0, 7);
        const cacheKey = `dashboard_${currentMonth}`;
        
        // 1-minute cache for dashboard
        if (dataStore.smsCache[cacheKey] && 
            (Date.now() - dataStore.smsCache[cacheKey].timestamp) < 60 * 1000) {
            return res.json(dataStore.smsCache[cacheKey].data);
        }
        
        // Fetch current month data
        const year = new Date().getFullYear();
        const month = new Date().getMonth() + 1;
        const dateStart = `${year}-${String(month).padStart(2, '0')}-01`;
        const dateEnd = new Date().toISOString().slice(0, 10);
        
        const jwtToken = generateVonageJWT();
        const headers = jwtToken ? {
            'Authorization': `Bearer ${jwtToken}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        } : {
            'Authorization': `Basic ${Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64')}`,
            'Content-Type': 'application/json'
        };
        
        const records = await fetchSMSDataWithPagination(headers, dateStart, dateEnd, true);
        const data = processRecords(records);
        
        // Create summary
        const summary = {
            success: true,
            month: currentMonth,
            totalSMS: data.total,
            totalCost: data.totalCost,
            activeCustomers: Object.keys(data.bySubAccount).length,
            topCountries: Object.entries(data.byCountry || {})
                .sort((a, b) => b[1].count - a[1].count)
                .slice(0, 5)
                .map(([name, info]) => ({
                    name,
                    count: info.count,
                    cost: info.cost
                })),
            topCustomers: Object.entries(data.bySubAccount || {})
                .sort((a, b) => b[1].count - a[1].count)
                .slice(0, 10)
                .map(([id, info]) => ({
                    apiKey: id,
                    name: info.accountName,
                    count: info.count,
                    cost: info.cost
                })),
            lastUpdated: new Date().toISOString()
        };
        
        // Cache for 1 minute
        dataStore.smsCache[cacheKey] = {
            data: summary,
            timestamp: Date.now()
        };
        
        res.json(summary);
        
    } catch (error) {
        console.error('Dashboard summary error:', error.message);
        res.json({
            success: false,
            error: error.message,
            totalSMS: 0,
            totalCost: 0,
            activeCustomers: 0
        });
    }
});

// Get complete 6-month history for all accounts
app.get('/api/vonage/usage/complete-history', authenticateToken, async (req, res) => {
    try {
        console.log('\n=== FETCHING COMPLETE 6-MONTH HISTORY ===');
        
        // Check cache
        const cacheKey = 'complete_history';
        if (dataStore.smsCache[cacheKey] && 
            (Date.now() - dataStore.smsCache[cacheKey].timestamp) < 30 * 60 * 1000) { // 30-minute cache
            return res.json(dataStore.smsCache[cacheKey].data);
        }
        
        const today = new Date();
        const months = [];
        
        // Get last 6 months plus current
        for (let i = 6; i >= 0; i--) {
            const d = new Date(today.getFullYear(), today.getMonth() - i, 1);
            months.push(d.toISOString().slice(0, 7));
        }
        
        // Get sub-accounts
        const subAccounts = await fetchSubAccounts();
        console.log(`Processing ${subAccounts.length} accounts over ${months.length} months`);
        
        const completeHistory = {
            accounts: {},
            monthlyTotals: {},
            dailyTotals: {},
            grandTotals: {
                sms: 0,
                cost: 0
            }
        };
        
        // Initialize accounts
        for (const account of subAccounts) {
            completeHistory.accounts[account.api_key] = {
                name: account.name,
                apiKey: account.api_key,
                monthlyData: {},
                totals: { sms: 0, cost: 0 }
            };
        }
        
        // Get JWT token
        const jwtToken = generateVonageJWT();
        const headers = jwtToken ? {
            'Authorization': `Bearer ${jwtToken}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        } : {
            'Authorization': `Basic ${Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64')}`,
            'Content-Type': 'application/json'
        };
        
        // Process each month
        for (const month of months) {
            console.log(`Fetching ${month}...`);
            
            const year = parseInt(month.split('-')[0]);
            const monthNum = parseInt(month.split('-')[1]);
            const dateStart = `${year}-${String(monthNum).padStart(2, '0')}-01`;
            const lastDay = new Date(year, monthNum, 0).getDate();
            const dateEnd = `${year}-${String(monthNum).padStart(2, '0')}-${String(lastDay).padStart(2, '0')}`;
            
            try {
                const records = await fetchSMSDataWithPagination(headers, dateStart, dateEnd, true);
                const monthData = processRecords(records);
                
                // Store monthly totals
                completeHistory.monthlyTotals[month] = {
                    sms: monthData.total,
                    cost: monthData.totalCost
                };
                
                // Store per-account monthly data
                for (const [accountId, accountData] of Object.entries(monthData.bySubAccount)) {
                    if (completeHistory.accounts[accountId]) {
                        completeHistory.accounts[accountId].monthlyData[month] = {
                            sms: accountData.count,
                            cost: accountData.cost
                        };
                        completeHistory.accounts[accountId].totals.sms += accountData.count;
                        completeHistory.accounts[accountId].totals.cost += accountData.cost;
                    }
                }
                
                // Store daily totals
                for (const [date, dayData] of Object.entries(monthData.byDate)) {
                    completeHistory.dailyTotals[date] = dayData;
                }
                
                // Update grand totals
                completeHistory.grandTotals.sms += monthData.total;
                completeHistory.grandTotals.cost += monthData.totalCost;
                
            } catch (error) {
                console.error(`Error fetching ${month}:`, error.message);
                completeHistory.monthlyTotals[month] = { sms: 0, cost: 0 };
            }
        }
        
        const result = {
            success: true,
            period: {
                start: months[0],
                end: months[months.length - 1],
                months: months
            },
            summary: {
                totalAccounts: Object.keys(completeHistory.accounts).length,
                totalSMS: completeHistory.grandTotals.sms,
                totalCost: completeHistory.grandTotals.cost,
                monthlyTotals: completeHistory.monthlyTotals
            },
            accounts: completeHistory.accounts,
            dailyTotals: completeHistory.dailyTotals
        };
        
        // Cache result
        dataStore.smsCache[cacheKey] = {
            data: result,
            timestamp: Date.now()
        };
        
        res.json(result);
        
    } catch (error) {
        console.error('Complete history error:', error.message);
        res.json({
            success: false,
            error: error.message
        });
    }
});

// Get usage for current month (alias for dashboard)
app.get('/api/vonage/usage/current', authenticateToken, async (req, res) => {
    req.query.month = new Date().toISOString().slice(0, 7);
    return app._router.handle(req, res);
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
                error: 'Mapping already exists'
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
    
    if (!process.env.JWT_SECRET) {
        console.warn('⚠️  JWT_SECRET: Using default (set in production!)');
    } else {
        console.log('✅ JWT_SECRET: Configured');
    }
    
    console.log('\n=== VONAGE API STATUS ===');
    if (!process.env.VONAGE_API_KEY) {
        console.error('❌ VONAGE_API_KEY: NOT SET');
    } else {
        console.log('✅ VONAGE_API_KEY:', process.env.VONAGE_API_KEY);
    }
    
    if (!process.env.VONAGE_API_SECRET) {
        console.error('❌ VONAGE_API_SECRET: NOT SET');
    } else {
        console.log('✅ VONAGE_API_SECRET: ***hidden***');
    }
    
    if (!process.env.VONAGE_APPLICATION_ID) {
        console.warn('⚠️  VONAGE_APPLICATION_ID: Not set (using Basic Auth)');
    } else {
        console.log('✅ VONAGE_APPLICATION_ID: Configured');
    }
    
    console.log('\n========================================\n');
});