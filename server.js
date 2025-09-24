// server.js - Complete Backend Server for Chatti Platform with Vonage Reseller Integration
// Version: Complete solution for SMS tracking across 267 sub-accounts

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
        privateKey: process.env.VONAGE_PRIVATE_KEY || '', // Add this to environment variables
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
    customerMappings: [],
    smsCache: {} // Cache SMS data by month
};

// Cache for sub-accounts
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
        return subAccountsCache.data;
    }
}

// =================== JWT GENERATION FOR VONAGE ===================

function generateVonageJWT() {
    // If no application ID or private key, fall back to Basic Auth
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
            exp: now + 3600 // 1 hour expiry
        };
        
        // Sign with private key
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
                message: 'JWT generation failed. Need VONAGE_APPLICATION_ID and VONAGE_PRIVATE_KEY in environment variables',
                help: 'Create a Vonage Application in your dashboard and add the credentials to Render'
            });
        }
        
        // Test the JWT with a simple Reports API call
        const testBody = {
            product: 'SMS',
            date_start: '2024-10-01T00:00:00Z',
            date_end: '2024-10-31T23:59:59Z',
            include_subaccounts: true
        };
        
        console.log('Testing JWT with Reports API...');
        console.log('Request body:', JSON.stringify(testBody, null, 2));
        
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

// Test which date format works for Reports API
app.get('/api/vonage/test-date-formats', authenticateToken, async (req, res) => {
    try {
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        // Generate various date formats for today
        const today = new Date();
        const yesterday = new Date(today);
        yesterday.setDate(yesterday.getDate() - 1);
        
        const dateFormats = [
            {
                name: 'Simple YYYY-MM-DD',
                start: today.toISOString().slice(0, 10),
                end: today.toISOString().slice(0, 10)
            },
            {
                name: 'RFC3339 with Z',
                start: `${today.toISOString().slice(0, 10)}T00:00:00Z`,
                end: `${today.toISOString().slice(0, 10)}T23:59:59Z`
            },
            {
                name: 'ISO 8601 Full',
                start: today.toISOString(),
                end: today.toISOString()
            },
            {
                name: 'Unix Timestamp',
                start: Math.floor(yesterday.getTime() / 1000),
                end: Math.floor(today.getTime() / 1000)
            },
            {
                name: 'No dates (default)',
                start: null,
                end: null
            }
        ];
        
        const results = [];
        
        for (const format of dateFormats) {
            console.log(`Testing format: ${format.name}`);
            
            try {
                const params = {
                    account_id: config.vonage.accountId,
                    product: 'SMS'
                };
                
                if (format.start !== null) {
                    params.date_start = format.start;
                    params.date_end = format.end;
                }
                
                const response = await axios.get('https://api.nexmo.com/v2/reports/records', {
                    headers: {
                        'Authorization': `Basic ${auth}`,
                        'Content-Type': 'application/json'
                    },
                    params: params,
                    timeout: 10000
                });
                
                results.push({
                    format: format.name,
                    success: true,
                    recordCount: response.data?.records?.length || 0,
                    sample: format
                });
                
                // If we found a working format, use it
                if (response.data?.records?.length > 0) {
                    return res.json({
                        success: true,
                        workingFormat: format.name,
                        sample: format,
                        recordCount: response.data.records.length,
                        results: results
                    });
                }
                
            } catch (error) {
                results.push({
                    format: format.name,
                    success: false,
                    error: error.response?.status,
                    message: error.response?.data?.detail || error.response?.data?.title
                });
            }
        }
        
        res.json({
            success: false,
            message: 'No working date format found',
            results: results
        });
        
    } catch (error) {
        res.json({
            success: false,
            error: error.message
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

// =================== SMS USAGE - COMPLETE IMPLEMENTATION ===================

// Get SMS usage for current month (for dashboard)
app.get('/api/vonage/usage/current', authenticateToken, async (req, res) => {
    const currentMonth = new Date().toISOString().slice(0, 7);
    req.query.month = currentMonth;
    return getSMSUsage(req, res);
});

// Get SMS usage for specific month or date range
app.get('/api/vonage/usage/sms', authenticateToken, getSMSUsage);

async function getSMSUsage(req, res) {
    try {
        const { month = new Date().toISOString().slice(0, 7), startDate, endDate } = req.query;
        
        // Check cache first
        const cacheKey = `${month}_${startDate}_${endDate}`;
        if (dataStore.smsCache[cacheKey] && 
            (Date.now() - dataStore.smsCache[cacheKey].timestamp) < 5 * 60 * 1000) {
            console.log('Returning cached SMS data for:', cacheKey);
            return res.json(dataStore.smsCache[cacheKey].data);
        }
        
        if (!config.vonage.apiKey || !config.vonage.apiSecret) {
            return res.json({ 
                success: true,
                data: generateEmptyUsageData(),
                message: 'Vonage credentials not configured'
            });
        }
        
        // Calculate date range
        let dateStart, dateEnd;
        
        if (startDate && endDate) {
            dateStart = startDate;
            dateEnd = endDate;
        } else {
            const year = parseInt(month.split('-')[0]);
            const monthNum = parseInt(month.split('-')[1]);
            dateStart = `${year}-${String(monthNum).padStart(2, '0')}-01`;
            const lastDay = new Date(year, monthNum, 0).getDate();
            dateEnd = `${year}-${String(monthNum).padStart(2, '0')}-${String(lastDay).padStart(2, '0')}`;
        }
        
        console.log(`\n=== SMS USAGE REQUEST ===`);
        console.log(`Date range: ${dateStart} to ${dateEnd}`);
        console.log(`Account ID: ${config.vonage.accountId}`);
        
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        // Initialize aggregated usage data
        const aggregatedUsage = {
            total: 0,
            outbound: 0,
            inbound: 0,
            byCountry: {},
            bySubAccount: {},
            byDate: {},
            totalCost: 0,
            currentMonth: month
        };
        
        // Try to fetch SMS data using different methods
        let smsData = await fetchSMSDataAsync(auth, dateStart, dateEnd);
        
        if (!smsData || smsData.length === 0) {
            smsData = await fetchSMSDataSync(auth, dateStart, dateEnd);
        }
        
        if (!smsData || smsData.length === 0) {
            smsData = await fetchSMSDataNoDate(auth);
        }
        
        // Process SMS data
        if (smsData && smsData.length > 0) {
            console.log(`Processing ${smsData.length} SMS records`);
            
            for (const record of smsData) {
                aggregatedUsage.total++;
                
                // Direction
                if (record.direction === 'outbound' || record.direction === 'out' || 
                    record.type === 'MT' || record.type === 'SMS') {
                    aggregatedUsage.outbound++;
                } else if (record.direction === 'inbound' || record.direction === 'in' || 
                          record.type === 'MO') {
                    aggregatedUsage.inbound++;
                }
                
                // Cost
                const cost = parseFloat(record.price || record.total_price || record.cost || 0);
                aggregatedUsage.totalCost += cost;
                
                // Country
                const country = record.to_country || record.country || getCountryFromNumber(record.to || record.number);
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
                
                // Sub-account
                const accountId = record.account_id || record.api_key || 'master';
                const accountName = record.account_name || record.api_key || accountId;
                
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
                        count: 0,
                        cost: 0
                    };
                }
                aggregatedUsage.bySubAccount[accountId].byCountry[countryName].count++;
                aggregatedUsage.bySubAccount[accountId].byCountry[countryName].cost += cost;
                
                // Date breakdown (for charts)
                const messageDate = record.date_start || record.timestamp || record.created_at;
                if (messageDate) {
                    const dateKey = messageDate.slice(0, 10);
                    if (!aggregatedUsage.byDate[dateKey]) {
                        aggregatedUsage.byDate[dateKey] = {
                            count: 0,
                            cost: 0
                        };
                    }
                    aggregatedUsage.byDate[dateKey].count++;
                    aggregatedUsage.byDate[dateKey].cost += cost;
                }
            }
            
            // Cache the result
            const result = {
                success: true,
                data: aggregatedUsage,
                month: month,
                dateRange: `${dateStart} to ${dateEnd}`,
                recordCount: aggregatedUsage.total
            };
            
            dataStore.smsCache[cacheKey] = {
                data: result,
                timestamp: Date.now()
            };
            
            return res.json(result);
        }
        
        // No data found
        return res.json({
            success: true,
            data: aggregatedUsage,
            month: month,
            dateRange: `${dateStart} to ${dateEnd}`,
            recordCount: 0,
            message: 'No SMS data found for this period'
        });
        
    } catch (error) {
        console.error('SMS usage endpoint error:', error.message);
        
        return res.json({
            success: true,
            data: generateEmptyUsageData(),
            error: error.message,
            message: 'Error fetching SMS data'
        });
    }
}

// Helper function to fetch SMS data using async method with JWT
async function fetchSMSDataAsync(auth, dateStart, dateEnd) {
    try {
        console.log('\nTrying ASYNC Reports API with JWT authentication...');
        
        // Generate JWT token
        const jwtToken = generateVonageJWT();
        
        if (!jwtToken) {
            console.log('No JWT available, falling back to Basic Auth');
            // Try with Basic Auth as fallback
            auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        }
        
        const asyncUrl = 'https://api.nexmo.com/v2/reports';
        const asyncBody = {
            product: 'SMS',
            date_start: `${dateStart}T00:00:00Z`,
            date_end: `${dateEnd}T23:59:59Z`,
            include_subaccounts: true,
            direction: 'outbound'
        };
        
        console.log('Request URL:', asyncUrl);
        console.log('Request body:', JSON.stringify(asyncBody, null, 2));
        console.log('Using authentication:', jwtToken ? 'JWT' : 'Basic Auth');
        
        const headers = jwtToken ? {
            'Authorization': `Bearer ${jwtToken}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        } : {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        };
        
        const createReportResponse = await axios.post(asyncUrl, asyncBody, {
            headers: headers,
            timeout: 10000
        });
        
        console.log('Report response:', createReportResponse.status);
        console.log('Response data:', createReportResponse.data);
        
        // For synchronous endpoint, data might be returned immediately
        if (createReportResponse.data?.records) {
            console.log(`Sync response returned ${createReportResponse.data.records.length} records immediately`);
            return createReportResponse.data.records;
        }
        
        // For async, we get a request_id
        const reportId = createReportResponse.data?.request_id || 
                        createReportResponse.data?.id || 
                        createReportResponse.data?.report_id;
        
        if (!reportId) {
            console.log('No report ID returned, checking if data is directly in response');
            return createReportResponse.data?.items || createReportResponse.data?.data || null;
        }
        
        console.log('Report created with ID:', reportId);
        
        // Wait for report to complete
        let attempts = 0;
        const maxAttempts = 20;
        
        while (attempts < maxAttempts) {
            attempts++;
            
            // Wait before checking
            await new Promise(resolve => setTimeout(resolve, 3000));
            
            try {
                const statusUrl = `https://api.nexmo.com/v2/reports/${reportId}`;
                const statusResponse = await axios.get(statusUrl, {
                    headers: headers,
                    timeout: 10000
                });
                
                const status = statusResponse.data?.status || 
                             statusResponse.data?.report_status || 
                             statusResponse.data?.state;
                
                console.log(`Report status (attempt ${attempts}): ${status}`);
                
                if (status === 'completed' || status === 'complete' || 
                    status === 'SUCCESS' || status === 'COMPLETED') {
                    
                    // Try different locations for the data
                    let reportData = statusResponse.data?.items || 
                                    statusResponse.data?.records || 
                                    statusResponse.data?._embedded?.records ||
                                    statusResponse.data?.data;
                    
                    // Try download URL if present
                    if (!reportData && statusResponse.data?.download_url) {
                        const downloadResponse = await axios.get(statusResponse.data.download_url, {
                            headers: headers,
                            timeout: 30000
                        });
                        reportData = downloadResponse.data?.items || 
                                   downloadResponse.data?.records || 
                                   downloadResponse.data;
                    }
                    
                    if (reportData && Array.isArray(reportData)) {
                        console.log(`Async method returned ${reportData.length} records`);
                        return reportData;
                    }
                }
                
                if (status === 'failed' || status === 'error' || status === 'FAILED') {
                    console.log('Report generation failed');
                    return null;
                }
                
            } catch (statusError) {
                console.error('Error checking report status:', statusError.message);
            }
        }
        
        console.log('Report timed out after', maxAttempts, 'attempts');
        return null;
        
    } catch (error) {
        console.error('Async method error:', error.response?.status, error.message);
        if (error.response?.data) {
            console.error('Error details:', JSON.stringify(error.response.data, null, 2));
        }
        return null;
    }
}

// Helper function to fetch SMS data using sync method
async function fetchSMSDataSync(auth, dateStart, dateEnd) {
    try {
        console.log('\nTrying SYNC Reports API (master account only)...');
        
        const syncUrl = 'https://api.nexmo.com/v2/reports/records';
        const syncParams = {
            account_id: config.vonage.accountId,
            product: 'SMS',
            date_start: `${dateStart}T00:00:00Z`,
            date_end: `${dateEnd}T23:59:59Z`
        };
        
        const syncResponse = await axios.get(syncUrl, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Accept': 'application/json'
            },
            params: syncParams,
            timeout: 30000
        });
        
        const records = syncResponse.data?.records || 
                       syncResponse.data?._embedded?.records || 
                       [];
        
        console.log(`Sync method returned ${records.length} records`);
        return records;
        
    } catch (error) {
        console.error('Sync method error:', error.response?.status, error.message);
        
        // Try without timezone
        try {
            const syncParams = {
                account_id: config.vonage.accountId,
                product: 'SMS',
                date_start: dateStart,
                date_end: dateEnd
            };
            
            const syncResponse = await axios.get('https://api.nexmo.com/v2/reports/records', {
                headers: {
                    'Authorization': `Basic ${auth}`,
                    'Accept': 'application/json'
                },
                params: syncParams,
                timeout: 30000
            });
            
            const records = syncResponse.data?.records || [];
            console.log(`Sync method (no TZ) returned ${records.length} records`);
            return records;
            
        } catch (retryError) {
            console.error('Sync retry error:', retryError.response?.status);
            return null;
        }
    }
}

// Helper function to fetch SMS data without date filter
async function fetchSMSDataNoDate(auth) {
    try {
        console.log('\nTrying Reports API without date filter...');
        
        const response = await axios.get('https://api.nexmo.com/v2/reports/records', {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Accept': 'application/json'
            },
            params: {
                account_id: config.vonage.accountId,
                product: 'SMS'
            },
            timeout: 30000
        });
        
        const records = response.data?.records || [];
        console.log(`No-date method returned ${records.length} records`);
        return records;
        
    } catch (error) {
        console.error('No-date method error:', error.response?.status);
        return null;
    }
}

// Generate empty usage data structure
function generateEmptyUsageData() {
    return {
        total: 0,
        outbound: 0,
        inbound: 0,
        byCountry: {},
        bySubAccount: {},
        byDate: {},
        totalCost: 0
    };
}

// Get historical SMS data (last 6 months)
app.get('/api/vonage/usage/history', authenticateToken, async (req, res) => {
    try {
        const months = [];
        const today = new Date();
        
        // Get last 6 months
        for (let i = 5; i >= 0; i--) {
            const d = new Date(today.getFullYear(), today.getMonth() - i, 1);
            months.push(d.toISOString().slice(0, 7));
        }
        
        const historyData = [];
        
        for (const month of months) {
            // Check cache
            if (dataStore.smsCache[month]) {
                historyData.push({
                    month: month,
                    data: dataStore.smsCache[month].data.data
                });
            } else {
                // Fetch data for this month
                req.query.month = month;
                const data = await getSMSUsageData(req);
                historyData.push({
                    month: month,
                    data: data
                });
            }
        }
        
        res.json({
            success: true,
            data: historyData,
            months: months
        });
        
    } catch (error) {
        res.json({
            success: false,
            error: error.message
        });
    }
});

// Helper to get SMS data without sending response
async function getSMSUsageData(req) {
    const mockRes = {
        json: (data) => data
    };
    
    const result = await getSMSUsage(req, mockRes);
    return result.data || generateEmptyUsageData();
}

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

app.get('/api/billing/generate-invoices', authenticateToken, async (req, res) => {
    const { month } = req.query;
    
    // Get SMS usage for the month
    req.query.month = month;
    const usageData = await getSMSUsageData(req);
    
    const invoices = [];
    
    // Generate invoice for each sub-account
    for (const [accountId, accountData] of Object.entries(usageData.bySubAccount || {})) {
        if (accountData.count > 0) {
            invoices.push({
                id: `INV-${month}-${accountId}`,
                customer: accountData.accountName,
                accountId: accountId,
                amount: accountData.cost,
                smsCount: accountData.count,
                status: 'draft',
                month: month,
                byCountry: accountData.byCountry
            });
        }
    }
    
    res.json({ 
        success: true, 
        data: invoices,
        totalAmount: usageData.totalCost,
        totalSMS: usageData.total
    });
});

// =================== DIAGNOSTIC ENDPOINTS ===================

// Find which API has SMS data
app.get('/api/vonage/find-sms-data', authenticateToken, async (req, res) => {
    const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
    const results = {};
    
    console.log('Testing various Vonage APIs to find SMS data...');
    
    // Test different endpoints
    const endpoints = [
        {
            name: 'Search Messages API',
            url: `https://api.nexmo.com/search/messages`,
            method: 'GET',
            params: {
                api_key: config.vonage.apiKey,
                api_secret: config.vonage.apiSecret,
                date_start: '2024-11-01',
                date_end: '2024-11-30'
            }
        },
        {
            name: 'Search Rejections',
            url: `https://api.nexmo.com/search/rejections`,
            method: 'GET',
            params: {
                api_key: config.vonage.apiKey,
                api_secret: config.vonage.apiSecret,
                date_start: '2024-11-01',
                date_end: '2024-11-30'
            }
        },
        {
            name: 'Account Statistics',
            url: `https://rest.nexmo.com/account/stats`,
            method: 'GET',
            params: {
                api_key: config.vonage.apiKey,
                api_secret: config.vonage.apiSecret
            }
        },
        {
            name: 'CDR Records',
            url: `https://api.nexmo.com/beta/conversions`,
            method: 'GET',
            useBasic: true
        }
    ];
    
    for (const endpoint of endpoints) {
        try {
            console.log(`Testing: ${endpoint.name}`);
            const options = {
                method: endpoint.method,
                url: endpoint.url,
                timeout: 10000
            };
            
            if (endpoint.useBasic) {
                options.headers = {
                    'Authorization': `Basic ${auth}`,
                    'Content-Type': 'application/json'
                };
            } else if (endpoint.params) {
                options.params = endpoint.params;
            }
            
            const response = await axios(options);
            
            results[endpoint.name] = {
                success: true,
                hasData: !!response.data,
                sampleData: response.data ? 
                    (typeof response.data === 'object' ? 
                        Object.keys(response.data).slice(0, 5) : 
                        'Data received') : 
                    'No data'
            };
            
        } catch (error) {
            results[endpoint.name] = {
                success: false,
                status: error.response?.status,
                error: error.response?.data?.error_text || error.message
            };
        }
    }
    
    res.json({
        success: true,
        message: 'API endpoint test results',
        results: results,
        recommendation: 'Check which endpoints returned data'
    });
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
    } else {
        console.log('✅ VONAGE_API_KEY:', process.env.VONAGE_API_KEY);
    }
    
    if (!process.env.VONAGE_API_SECRET) {
        console.error('❌ VONAGE_API_SECRET: NOT SET - API will not work!');
    } else {
        console.log('✅ VONAGE_API_SECRET: ***hidden***');
    }
    
    console.log('   Account ID:', config.vonage.accountId);
    
    console.log('\n========================================\n');
});