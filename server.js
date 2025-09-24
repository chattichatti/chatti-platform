// server.js - Complete Backend Server for Chatti Platform with Vonage Reseller Integration
// Version: Fixed with CORRECT async Reports API URLs per Vonage documentation

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const AdmZip = require('adm-zip');

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Simple user store
const users = [
    {
        id: 1,
        email: 'admin@chatti.com',
        passwordHash: process.env.ADMIN_PASS_SHA256 || '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9',
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
        return [];
    }
}

// =================== JWT GENERATION FOR VONAGE ===================

function generateVonageJWT() {
    if (!config.vonage.applicationId || !config.vonage.privateKey) {
        console.warn('Cannot generate JWT - missing applicationId or privateKey');
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

// =============== Reports API (Async) - CORRECTED URLS ===============

async function createAsyncReport(headers, dateStart, dateEnd) {
    const body = {
        product: 'SMS',
        // Omit account_id when aggregating across subaccounts
        date_start: `${dateStart}T00:00:00Z`,
        date_end: `${dateEnd}T23:59:59Z`,
        direction: 'outbound',
        include_subaccounts: true,
        async: true,  // This parameter makes it async
        callback_url: null  // Optional webhook
    };
    
    console.log('Creating async report with body:', JSON.stringify(body, null, 2));
    
    // CORRECTED: Use /v2/reports NOT /v2/reports/async
    const url = 'https://api.nexmo.com/v2/reports';
    
    try {
        const r = await axios.post(url, body, { headers, timeout: 30000 });
        const requestId = r.data?.request_id || r.data?.id;
        
        if (requestId) {
            console.log(`Async report created successfully with request_id: ${requestId}`);
        } else if (r.data?.records) {
            // Sometimes returns synchronous data directly
            console.log('Got synchronous response with records');
            return { type: 'sync', data: r.data.records };
        }
        
        return { type: 'async', requestId };
    } catch (error) {
        console.error('Create async report error:', error.response?.status, error.response?.data);
        throw error;
    }
}

async function pollAsyncReport(headers, requestId, timeoutMs = 10 * 60 * 1000) {
    // CORRECTED: Use /v2/reports/{request_id} NOT /v2/reports/async/{request_id}
    const statusUrl = `https://api.nexmo.com/v2/reports/${requestId}`;
    const start = Date.now();
    let attempts = 0;
    
    while (Date.now() - start < timeoutMs) {
        await new Promise(r => setTimeout(r, 5000)); // Wait 5 seconds between polls
        attempts++;
        
        try {
            const s = await axios.get(statusUrl, { headers, timeout: 30000 });
            const state = s.data?.status || s.data?.state || s.data?.request_status;
            
            console.log(`Poll attempt ${attempts}: Status = ${state}`);
            
            if (/completed|complete|success|succeeded/i.test(state)) {
                // Check for download URL or embedded data
                const downloadUrl = s.data?.download_url || s.data?.links?.download || s.data?._links?.download?.href;
                const records = s.data?.records || s.data?.items;
                
                if (downloadUrl) {
                    console.log('Report completed with download URL');
                    return { type: 'download', url: downloadUrl };
                } else if (records) {
                    console.log('Report completed with embedded data');
                    return { type: 'embedded', data: records };
                }
            }
            
            if (/failed|error/i.test(state)) {
                throw new Error(`Async report failed: ${state} - ${s.data?.error || ''}`);
            }
        } catch (pollError) {
            if (pollError.response?.status === 404) {
                console.error('Report not found - may have expired or invalid request_id');
                throw new Error('Report not found');
            }
            throw pollError;
        }
    }
    
    throw new Error('Async report timed out after ' + attempts + ' attempts');
}

async function downloadAndExtractZip(headers, url) {
    console.log('Downloading ZIP from:', url);
    
    try {
        const dl = await axios.get(url, { 
            headers, 
            responseType: 'arraybuffer', 
            timeout: 180000 // 3 minutes for large downloads
        });
        
        const zip = new AdmZip(Buffer.from(dl.data));
        const entries = zip.getEntries();
        
        console.log(`ZIP contains ${entries.length} files`);
        
        let records = [];
        
        for (const e of entries) {
            const name = e.entryName.toLowerCase();
            const text = e.getData().toString('utf8');
            
            console.log(`Processing file: ${e.entryName}`);
            
            if (name.endsWith('.json')) {
                try {
                    const parsed = JSON.parse(text);
                    const arr = parsed.records || parsed.items || parsed.data || parsed;
                    if (Array.isArray(arr)) {
                        records.push(...arr);
                        console.log(`Extracted ${arr.length} records from JSON`);
                    }
                } catch (jsonError) {
                    console.error('Failed to parse JSON:', jsonError.message);
                }
            } else if (name.endsWith('.csv')) {
                // Simple CSV parser
                const lines = text.trim().split(/\r?\n/);
                if (lines.length > 1) {
                    const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''));
                    
                    for (let i = 1; i < lines.length; i++) {
                        const values = lines[i].split(',').map(v => v.trim().replace(/^"|"$/g, ''));
                        const record = {};
                        headers.forEach((h, idx) => {
                            record[h] = values[idx];
                        });
                        records.push(record);
                    }
                    console.log(`Extracted ${lines.length - 1} records from CSV`);
                }
            }
        }
        
        return records;
    } catch (downloadError) {
        console.error('Download/extract error:', downloadError.message);
        throw downloadError;
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
        
        if (record.direction === 'outbound' || record.type === 'MT') {
            aggregated.outbound++;
        } else {
            aggregated.inbound++;
        }
        
        const cost = parseFloat(record.price || record.total_price || record.cost || 0);
        aggregated.totalCost += cost;
        
        const country = record.to_country || record.country || getCountryFromNumber(record.to);
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
                cost: 0
            };
        }
        aggregated.bySubAccount[accountId].count++;
        aggregated.bySubAccount[accountId].cost += cost;
        
        const messageDate = record.date_start || record.timestamp || record.created_at;
        if (messageDate) {
            const dateKey = messageDate.slice(0, 10);
            if (!aggregated.byDate[dateKey]) {
                aggregated.byDate[dateKey] = { count: 0, cost: 0 };
            }
            aggregated.byDate[dateKey].count++;
            aggregated.byDate[dateKey].cost += cost;
        }
    }
    
    return aggregated;
}

// Fallback synchronous method (master account only)
async function fetchSyncReportData(headers, dateStart, dateEnd) {
    try {
        console.log('\n=== FALLBACK: Trying synchronous Reports API (master only) ===');
        
        const body = {
            product: 'SMS',
            account_id: config.vonage.accountId,
            date_start: `${dateStart}T00:00:00Z`,
            date_end: `${dateEnd}T23:59:59Z`,
            direction: 'outbound'
            // NO async parameter = synchronous
        };
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000
        });
        
        console.log(`Sync response: ${response.data?.records?.length || 0} records`);
        return response.data?.records || [];
        
    } catch (error) {
        console.error('Sync method error:', error.response?.status, error.response?.data || error.message);
        return [];
    }
}

// =================== FRONTEND ROUTES ===================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// =================== AUTHENTICATION ROUTES ===================

app.post('/api/login', async (req, res) => {
    try {
        const { email, passHash } = req.body;
        
        const user = users.find(u => u.email === email);
        
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }
        
        // Simple hash comparison
        if (passHash !== user.passwordHash) {
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
    res.json({
        success: true,
        message: 'Reports API endpoint available'
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

// Sub-account SMS usage
app.get('/api/vonage/subaccounts/:id/sms-usage', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        res.json({ 
            success: true, 
            data: {
                subAccountKey: id,
                total: 0,
                totalCost: 0,
                message: 'Individual sub-account data requires sub-account API secret'
            }
        });
        
    } catch (error) {
        res.json({ 
            success: false, 
            error: error.message 
        });
    }
});

// =================== SMS USAGE ENDPOINTS ===================

// SMS usage endpoint - UPDATED WITH CORRECTED ASYNC URLS
app.get('/api/vonage/usage/sms', authenticateToken, async (req, res) => {
    try {
        const { month = new Date().toISOString().slice(0, 7) } = req.query;
        
        // Check cache first
        const cacheKey = `sms_${month}`;
        if (dataStore.smsCache[cacheKey] && 
            (Date.now() - dataStore.smsCache[cacheKey].timestamp) < 5 * 60 * 1000) {
            console.log('Returning cached data for', month);
            return res.json(dataStore.smsCache[cacheKey].data);
        }
        
        const year = parseInt(month.split('-')[0]);
        const monthNum = parseInt(month.split('-')[1]);
        const dateStart = `${year}-${String(monthNum).padStart(2, '0')}-01`;
        const lastDay = new Date(year, monthNum, 0).getDate();
        const dateEnd = `${year}-${String(monthNum).padStart(2, '0')}-${String(lastDay).padStart(2, '0')}`;
        
        console.log(`\n=== SMS USAGE REQUEST FOR ${month} ===`);
        console.log(`Date range: ${dateStart} to ${dateEnd}`);
        
        // Prepare authentication headers - ASYNC REQUIRES JWT
        const jwtToken = generateVonageJWT();
        
        if (!jwtToken) {
            console.error('Cannot generate JWT - check VONAGE_APPLICATION_ID and VONAGE_PRIVATE_KEY');
            return res.json({
                success: false,
                error: 'JWT generation failed - check application configuration',
                data: processRecords([])
            });
        }
        
        const headers = {
            'Authorization': `Bearer ${jwtToken}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        };
        
        // Use the CORRECTED async flow
        let records = [];
        try {
            console.log('=== ASYNC REPORT: Using corrected URLs ===');
            
            const createResult = await createAsyncReport(headers, dateStart, dateEnd);
            
            if (createResult.type === 'sync') {
                // Got synchronous data directly
                console.log('Got synchronous response directly');
                records = createResult.data;
            } else {
                // Got async request_id, need to poll
                console.log(`Polling for async report: ${createResult.requestId}`);
                const pollResult = await pollAsyncReport(headers, createResult.requestId);
                
                if (pollResult.type === 'download') {
                    records = await downloadAndExtractZip(headers, pollResult.url);
                } else if (pollResult.type === 'embedded') {
                    records = pollResult.data;
                }
            }
            
            console.log(`Total records retrieved: ${records.length}`);
            
        } catch (asyncError) {
            console.error('Async flow failed:', asyncError.message);
            
            if (asyncError.response?.data) {
                console.error('Error details:', JSON.stringify(asyncError.response.data, null, 2));
            }
            
            // Last resort: master-only sync (won't include subaccounts)
            console.log('Falling back to synchronous method (master account only)...');
            records = await fetchSyncReportData(headers, dateStart, dateEnd);
        }
        
        // Process and return the records
        const aggregatedData = processRecords(records);
        
        const result = {
            success: true,
            data: aggregatedData,
            month: month,
            dateRange: `${dateStart} to ${dateEnd}`,
            recordCount: aggregatedData.total,
            method: records.length > 0 ? 'async-corrected' : 'fallback'
        };
        
        // Cache the result
        dataStore.smsCache[cacheKey] = {
            data: result,
            timestamp: Date.now()
        };
        
        res.json(result);
        
    } catch (error) {
        console.error('SMS usage endpoint error:', error);
        res.status(500).json({
            success: false,
            error: error.message,
            data: processRecords([])
        });
    }
});

// Current month usage
app.get('/api/vonage/usage/current', authenticateToken, (req, res) => {
    const month = new Date().toISOString().slice(0, 7);
    res.redirect(`/api/vonage/usage/sms?month=${month}`);
});

// Dashboard summary
app.get('/api/vonage/dashboard/summary', authenticateToken, async (req, res) => {
    try {
        const currentMonth = new Date().toISOString().slice(0, 7);
        const year = new Date().getFullYear();
        const month = new Date().getMonth() + 1;
        const dateStart = `${year}-${String(month).padStart(2, '0')}-01`;
        const dateEnd = new Date().toISOString().slice(0, 10);
        
        const jwtToken = generateVonageJWT();
        
        if (!jwtToken) {
            return res.json({
                success: false,
                error: 'JWT generation failed',
                totalSMS: 0,
                totalCost: 0
            });
        }
        
        const headers = {
            'Authorization': `Bearer ${jwtToken}`,
            'Content-Type': 'application/json'
        };
        
        let records = [];
        try {
            const createResult = await createAsyncReport(headers, dateStart, dateEnd);
            
            if (createResult.type === 'sync') {
                records = createResult.data;
            } else {
                const pollResult = await pollAsyncReport(headers, createResult.requestId);
                
                if (pollResult.type === 'download') {
                    records = await downloadAndExtractZip(headers, pollResult.url);
                } else if (pollResult.type === 'embedded') {
                    records = pollResult.data;
                }
            }
        } catch (e) {
            console.error('Dashboard async error:', e.message);
            records = await fetchSyncReportData(headers, dateStart, dateEnd);
        }
        
        const data = processRecords(records);
        
        const summary = {
            success: true,
            month: currentMonth,
            totalSMS: data.total,
            totalCost: data.totalCost,
            activeCustomers: Object.keys(data.bySubAccount).length,
            lastUpdated: new Date().toISOString()
        };
        
        res.json(summary);
        
    } catch (error) {
        res.json({
            success: false,
            error: error.message,
            totalSMS: 0,
            totalCost: 0
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
    
    console.log('\n=== VONAGE API STATUS ===');
    if (!process.env.VONAGE_API_KEY) {
        console.error('❌ VONAGE_API_KEY: NOT SET');
    } else {
        console.log('✅ VONAGE_API_KEY:', process.env.VONAGE_API_KEY);
    }
    
    if (!process.env.VONAGE_APPLICATION_ID) {
        console.warn('⚠️  VONAGE_APPLICATION_ID: Not set (async reports will fail)');
    } else {
        console.log('✅ VONAGE_APPLICATION_ID: Configured');
    }
    
    if (!process.env.VONAGE_PRIVATE_KEY) {
        console.warn('⚠️  VONAGE_PRIVATE_KEY: Not set (async reports will fail)');
    } else {
        console.log('✅ VONAGE_PRIVATE_KEY: Configured');
    }
    
    console.log('\n========================================\n');
});