// server.js - Complete Backend Server for Chatti Platform with Vonage Reseller Integration
// Version: Security-hardened with proper async Reports API

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const dotenv = require('dotenv');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

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

// =================== SECURITY FUNCTIONS ===================

function constantTimeEqualHex(a, b) {
    // Constant-time comparison for hex strings
    if (!a || !b || a.length !== b.length) return false;
    try {
        const ab = Buffer.from(a, 'hex');
        const bb = Buffer.from(b, 'hex');
        if (ab.length !== bb.length) return false;
        return crypto.timingSafeEqual(ab, bb);
    } catch (e) {
        return false;
    }
}

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
        console.log('No Vonage Application configured');
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
    
    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
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

// Secure login with hash comparison
app.post('/api/login', async (req, res) => {
    try {
        const { email, passHash } = req.body; // passHash is SHA-256 hex from client
        
        const okEmail = email && email.toLowerCase() === (process.env.ADMIN_USER_EMAIL || 'admin@chatti.com').toLowerCase();
        const okHash = passHash && constantTimeEqualHex(passHash, process.env.ADMIN_PASS_SHA256 || '');
        
        if (!okEmail || !okHash) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }
        
        // Issue UI token (not related to Vonage JWT)
        const token = jwt.sign(
            { sub: email, role: 'admin' },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '12h' }
        );
        
        res.json({
            success: true,
            token,
            user: {
                email: email,
                role: 'admin',
                name: 'Admin User'
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Login error' 
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
        res.json({ 
            success: false, 
            error: error.response?.data || error.message 
        });
    }
});

// Test Reports API endpoint
app.get('/api/vonage/test-reports', authenticateToken, (req, res) => {
    const missing = [];
    if (!process.env.VONAGE_APPLICATION_ID) missing.push('VONAGE_APPLICATION_ID');
    if (!process.env.VONAGE_PRIVATE_KEY) missing.push('VONAGE_PRIVATE_KEY');
    
    res.json({
        success: missing.length === 0,
        message: missing.length ? `Missing env: ${missing.join(', ')}` : 'Reports API configuration OK'
    });
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
        return res.json({ 
            success: true,
            data: [],
            count: 0,
            error: error.message
        });
    }
});

// Per-subaccount SMS usage
app.get('/api/vonage/subaccounts/:id/sms-usage', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const jwtToken = generateVonageJWT();
        
        if (!jwtToken) {
            return res.json({
                success: false,
                error: 'JWT not configured'
            });
        }
        
        const headers = {
            'Authorization': `Bearer ${jwtToken}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        };
        
        // Last 30 days
        const end = new Date();
        const start = new Date();
        start.setDate(end.getDate() - 30);
        const fmt = d => d.toISOString().slice(0, 10);
        
        const body = {
            product: 'SMS',
            account_id: id,
            date_start: `${fmt(start)}T00:00:00Z`,
            date_end: `${fmt(end)}T23:59:59Z`,
            direction: 'outbound'
        };
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, { 
            headers, 
            timeout: 45000 
        });
        
        const records = response.data?.records || [];
        const processed = processRecords(records);
        
        res.json({ 
            success: true, 
            data: { 
                totalSMS: processed.total, 
                totalCost: processed.totalCost 
            } 
        });
        
    } catch (error) {
        res.json({ 
            success: false, 
            error: error.response?.data || error.message 
        });
    }
});

// =================== SMS DATA PROCESSING ===================

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
    
    if (!Array.isArray(records)) return aggregated;
    
    for (const record of records) {
        aggregated.total++;
        
        if (record.direction === 'outbound' || record.direction === 'out' || 
            record.type === 'MT' || record.type === 'SMS') {
            aggregated.outbound++;
        } else {
            aggregated.inbound++;
        }
        
        const cost = parseFloat(
            record.price || 
            record.total_price || 
            record.cost || 
            record.charge || 
            record.amount || 
            record.rate ||
            0
        );
        
        aggregated.totalCost += cost;
        
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
        
        const accountId = record.account_id || record.api_key || 'master';
        const accountName = record.account_name || accountId;
        
        if (!aggregated.bySubAccount[accountId]) {
            aggregated.bySubAccount[accountId] = {
                accountId: accountId,
                accountName: accountName,
                count: 0,
                cost: 0,
                byCountry: {}
            };
        }
        aggregated.bySubAccount[accountId].count++;
        aggregated.bySubAccount[accountId].cost += cost;
        
        const messageDate = record.date_start || record.timestamp || record.created_at || record.date;
        if (messageDate) {
            const dateKey = messageDate.slice(0, 10);
            if (!aggregated.byDate[dateKey]) {
                aggregated.byDate[dateKey] = {
                    count: 0,
                    cost: 0
                };
            }
            aggregated.byDate[dateKey].count++;
            aggregated.byDate[dateKey].cost += cost;
        }
    }
    
    return aggregated;
}

// =================== ASYNC REPORTS API (CORRECT IMPLEMENTATION) ===================

async function createAndWaitForAsyncReport(headers, dateStart, dateEnd) {
    try {
        console.log('\n=== CREATING ASYNC REPORT ===');
        
        // Step 1: Create async report
        const createBody = {
            product: 'SMS',
            date_start: `${dateStart}T00:00:00Z`,
            date_end: `${dateEnd}T23:59:59Z`,
            direction: 'outbound',
            include_subaccounts: true
        };
        
        console.log('Creating async report with:', JSON.stringify(createBody, null, 2));
        
        const createResponse = await axios.post('https://api.nexmo.com/v2/reports/async', createBody, { 
            headers, 
            timeout: 30000 
        });
        
        const requestId = createResponse.data?.request_id || createResponse.data?.id;
        
        if (!requestId) {
            console.log('No request_id returned');
            return [];
        }
        
        console.log('Async report created with request_id:', requestId);
        
        // Step 2: Poll for completion
        const statusUrl = `https://api.nexmo.com/v2/reports/async/${requestId}`;
        const started = Date.now();
        
        while (Date.now() - started < 10 * 60 * 1000) { // 10 minutes max
            await new Promise(resolve => setTimeout(resolve, 5000));
            
            try {
                const statusResponse = await axios.get(statusUrl, { 
                    headers, 
                    timeout: 30000 
                });
                
                const state = statusResponse.data?.status || statusResponse.data?.state;
                console.log('Report status:', state);
                
                if (/completed|complete|success/i.test(state)) {
                    if (statusResponse.data?.download_url) {
                        console.log('Downloading report...');
                        const downloadResponse = await axios.get(statusResponse.data.download_url, { 
                            headers, 
                            timeout: 120000 
                        });
                        const records = downloadResponse.data?.records || downloadResponse.data?.items || downloadResponse.data;
                        return Array.isArray(records) ? records : [];
                    }
                    const records = statusResponse.data?.records || statusResponse.data?.items || statusResponse.data?._embedded?.records;
                    return Array.isArray(records) ? records : [];
                }
                
                if (/failed|error/i.test(state)) {
                    console.error('Report generation failed');
                    break;
                }
            } catch (pollError) {
                console.error('Poll error:', pollError.message);
            }
        }
        
        console.log('Async report timed out or failed');
        return [];
        
    } catch (error) {
        console.error('Async report error:', error.response?.status, error.message);
        // Fall back to sync if async not available
        if (error.response?.status === 405 || error.response?.status === 404) {
            console.log('Async endpoint not available');
        }
        return [];
    }
}

// Compatibility shim
async function fetchSMSDataWithPagination(headers, dateStart, dateEnd) {
    // Try async first
    const records = await createAndWaitForAsyncReport(headers, dateStart, dateEnd);
    if (records.length > 0) return records;
    
    // Fall back to sync
    console.log('Falling back to synchronous request...');
    try {
        const body = {
            product: 'SMS',
            date_start: `${dateStart}T00:00:00Z`,
            date_end: `${dateEnd}T23:59:59Z`,
            direction: 'outbound'
        };
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000
        });
        
        return response.data?.records || [];
    } catch (error) {
        console.error('Sync fallback error:', error.response?.status);
        return [];
    }
}

// =================== SMS USAGE ENDPOINTS ===================

// Get SMS usage for a specific month
app.get('/api/vonage/usage/sms', authenticateToken, async (req, res) => {
    try {
        const { month = new Date().toISOString().slice(0, 7) } = req.query;
        
        const cacheKey = `sms_${month}`;
        if (dataStore.smsCache[cacheKey] && 
            (Date.now() - dataStore.smsCache[cacheKey].timestamp) < 5 * 60 * 1000) {
            return res.json(dataStore.smsCache[cacheKey].data);
        }
        
        const year = parseInt(month.split('-')[0]);
        const monthNum = parseInt(month.split('-')[1]);
        const dateStart = `${year}-${String(monthNum).padStart(2, '0')}-01`;
        const lastDay = new Date(year, monthNum, 0).getDate();
        const dateEnd = `${year}-${String(monthNum).padStart(2, '0')}-${String(lastDay).padStart(2, '0')}`;
        
        console.log(`\n=== SMS USAGE REQUEST ===`);
        console.log(`Month: ${month}`);
        console.log(`Date range: ${dateStart} to ${dateEnd}`);
        
        const jwtToken = generateVonageJWT();
        const headers = jwtToken ? {
            'Authorization': `Bearer ${jwtToken}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        } : {
            'Authorization': `Basic ${Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64')}`,
            'Content-Type': 'application/json'
        };
        
        const records = await fetchSMSDataWithPagination(headers, dateStart, dateEnd);
        const aggregatedData = processRecords(records);
        
        const result = {
            success: true,
            data: aggregatedData,
            month: month,
            dateRange: `${dateStart} to ${dateEnd}`,
            recordCount: aggregatedData.total,
            accountCount: Object.keys(aggregatedData.bySubAccount).length
        };
        
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
            data: processRecords([])
        });
    }
});

// Current month redirect (fixed)
app.get('/api/vonage/usage/current', authenticateToken, (req, res) => {
    const month = new Date().toISOString().slice(0, 7);
    res.redirect(302, `/api/vonage/usage/sms?month=${month}`);
});

// Dashboard summary
app.get('/api/vonage/dashboard/summary', authenticateToken, async (req, res) => {
    try {
        const currentMonth = new Date().toISOString().slice(0, 7);
        const cacheKey = `dashboard_${currentMonth}`;
        
        if (dataStore.smsCache[cacheKey] && 
            (Date.now() - dataStore.smsCache[cacheKey].timestamp) < 60 * 1000) {
            return res.json(dataStore.smsCache[cacheKey].data);
        }
        
        const year = new Date().getFullYear();
        const month = new Date().getMonth() + 1;
        const dateStart = `${year}-${String(month).padStart(2, '0')}-01`;
        const dateEnd = new Date().toISOString().slice(0, 10);
        
        const jwtToken = generateVonageJWT();
        const headers = jwtToken ? {
            'Authorization': `Bearer ${jwtToken}`,
            'Content-Type': 'application/json'
        } : {
            'Authorization': `Basic ${Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64')}`,
            'Content-Type': 'application/json'
        };
        
        const records = await fetchSMSDataWithPagination(headers, dateStart, dateEnd);
        const data = processRecords(records);
        
        const summary = {
            success: true,
            month: currentMonth,
            totalSMS: data.total,
            totalCost: data.totalCost,
            activeCustomers: Object.keys(data.bySubAccount).length,
            lastUpdated: new Date().toISOString()
        };
        
        dataStore.smsCache[cacheKey] = {
            data: summary,
            timestamp: Date.now()
        };
        
        res.json(summary);
        
    } catch (error) {
        res.json({
            success: false,
            error: error.message,
            totalSMS: 0,
            totalCost: 0,
            activeCustomers: 0
        });
    }
});

// =================== OTHER ENDPOINTS ===================

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
    
    if (!process.env.ADMIN_PASS_SHA256) {
        console.warn('⚠️  ADMIN_PASS_SHA256: Not set - login will fail');
    } else {
        console.log('✅ ADMIN_PASS_SHA256: Configured');
    }
    
    console.log('\n=== VONAGE API STATUS ===');
    if (!process.env.VONAGE_API_KEY) {
        console.error('❌ VONAGE_API_KEY: NOT SET');
    } else {
        console.log('✅ VONAGE_API_KEY:', process.env.VONAGE_API_KEY);
    }
    
    if (!process.env.VONAGE_APPLICATION_ID) {
        console.warn('⚠️  VONAGE_APPLICATION_ID: Not set (JWT disabled)');
    } else {
        console.log('✅ VONAGE_APPLICATION_ID: Configured');
    }
    
    console.log('\n========================================\n');
});