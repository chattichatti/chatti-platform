// server.js - Complete Backend Server for Chatti Platform with SAFE SMS Reporting
// Version: Safe individual account queries to prevent excessive charges

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const dotenv = require('dotenv');
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
        accountId: String(process.env.VONAGE_ACCOUNT_ID || '4c42609f'), // Corrected from f3fa74ea
        baseUrl: 'https://rest.nexmo.com',
        apiBaseUrl: 'https://api.nexmo.com'
    }
};

// Store for data
let dataStore = {
    smsCache: {}
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
        
        // Use country from record or detect from number
        const country = record.country || record.to_country || getCountryFromNumber(record.to);
        const countryName = record.country_name || getCountryName(country);
        
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
        
        if (!aggregated.bySubAccount[accountId]) {
            aggregated.bySubAccount[accountId] = {
                accountId: accountId,
                count: 0,
                cost: 0
            };
        }
        aggregated.bySubAccount[accountId].count++;
        aggregated.bySubAccount[accountId].cost += cost;
        
        const messageDate = record.date_finalized || record.date_received || record.date_start || record.timestamp;
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

// =================== SAFE SMS REPORTING - ONE ACCOUNT AT A TIME ===================

// Helper to get sub-accounts list
async function getSubAccountsList() {
    try {
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        const url = `https://api.nexmo.com/accounts/${config.vonage.accountId}/subaccounts`;
        
        const response = await axios.get(url, {
            headers: { 'Authorization': `Basic ${auth}` },
            timeout: 10000
        });
        
        let accounts = [];
        if (response.data?._embedded?.subaccounts) {
            accounts = response.data._embedded.subaccounts;
        }
        
        // Add the specific account from CSV if not in list
        const csvAccount = 'f3fa74ea';
        if (!accounts.find(a => a.api_key === csvAccount)) {
            accounts.push({ api_key: csvAccount, name: 'Account from CSV' });
        }
        
        return accounts;
    } catch (error) {
        console.error('Error fetching sub-accounts:', error.message);
        return [];
    }
}

// SAFE polling for single account reports (should complete quickly)
async function pollSingleAccountReport(requestId, headers, accountId) {
    const maxAttempts = 10; // Only 100 seconds for single accounts
    const pollInterval = 10000; // 10 seconds
    
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            const statusUrl = `https://api.nexmo.com/v2/reports/${requestId}`;
            const response = await axios.get(statusUrl, {
                headers,
                timeout: 10000,
                validateStatus: (status) => status < 500
            });
            
            const status = response.data?.status || 'unknown';
            console.log(`  Poll ${attempt}/${maxAttempts} for ${accountId}: ${status}`);
            
            if (status === 'completed' || status === 'COMPLETED') {
                // Check for download URL
                if (response.data?.download_url) {
                    console.log(`  📥 Downloading report for ${accountId}`);
                    try {
                        const downloadResponse = await axios.get(response.data.download_url, {
                            headers,
                            timeout: 30000
                        });
                        
                        if (downloadResponse.data?.records) {
                            console.log(`  ✅ Downloaded ${downloadResponse.data.records.length} records for ${accountId}`);
                            return downloadResponse.data.records;
                        }
                    } catch (dlError) {
                        console.error(`  ❌ Download failed for ${accountId}:`, dlError.message);
                    }
                }
                
                // Check for direct records
                if (response.data?.records) {
                    console.log(`  ✅ Got ${response.data.records.length} records for ${accountId}`);
                    return response.data.records;
                }
                
                return [];
            }
            
            if (status === 'failed' || status === 'FAILED') {
                console.error(`  ❌ Report failed for ${accountId}`);
                return [];
            }
            
            // Wait before next poll
            if (attempt < maxAttempts) {
                await new Promise(resolve => setTimeout(resolve, pollInterval));
            }
        } catch (error) {
            console.error(`  Poll error for ${accountId}:`, error.message);
            if (attempt === maxAttempts) return [];
        }
    }
    
    console.warn(`  ⏱️ Timeout polling ${accountId} after ${maxAttempts} attempts`);
    return [];
}

// Get SMS for a specific date range - SIMPLIFIED
async function getSMSForDateRange(accountId, dateStart, dateEnd) {
    try {
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        const headers = {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json'
        };
        
        const body = {
            "account_id": accountId,
            "product": "SMS",
            "direction": "outbound",
            "date_start": `${dateStart}T00:00:00+0000`,
            "date_end": `${dateEnd}T23:59:59+0000`
        };
        
        console.log(`Requesting SMS for ${accountId}: ${dateStart} to ${dateEnd}`);
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000,
            validateStatus: (status) => status < 500
        });
        
        // Synchronous response
        if (response.data?.records && Array.isArray(response.data.records)) {
            console.log(`Got ${response.data.records.length} records immediately`);
            return response.data.records;
        }
        
        // Async response - poll for it
        if (response.data?.request_id) {
            console.log(`Got async request_id: ${response.data.request_id}`);
            
            // Simple polling - 10 attempts, 5 seconds apart
            for (let i = 1; i <= 10; i++) {
                await new Promise(resolve => setTimeout(resolve, 5000));
                
                const statusUrl = `https://api.nexmo.com/v2/reports/${response.data.request_id}`;
                const statusResponse = await axios.get(statusUrl, { headers, timeout: 10000 });
                
                console.log(`Poll ${i}/10: ${statusResponse.data?.status}`);
                
                if (statusResponse.data?.status === 'completed' || statusResponse.data?.status === 'COMPLETED') {
                    // Download the results
                    if (statusResponse.data?.download_url) {
                        const downloadResponse = await axios.get(statusResponse.data.download_url, { 
                            headers, 
                            timeout: 30000 
                        });
                        if (downloadResponse.data?.records) {
                            console.log(`Downloaded ${downloadResponse.data.records.length} records`);
                            return downloadResponse.data.records;
                        }
                    }
                    // Or get direct records
                    if (statusResponse.data?.records) {
                        return statusResponse.data.records;
                    }
                }
            }
        }
        
        console.log('No records found');
        return [];
        
    } catch (error) {
        console.error(`Error: ${error.message}`);
        return [];
    }
}

// WORKING endpoint - get yesterday's data where we KNOW there's data
app.get('/api/vonage/usage/yesterday', authenticateToken, async (req, res) => {
    try {
        const yesterday = '2025-09-24'; // Your CSV shows data for this date
        console.log(`\n=== GETTING YESTERDAY'S DATA (${yesterday}) ===`);
        
        // Get data for the accounts we know have data
        const accounts = ['f3fa74ea', config.vonage.accountId]; // Start with known accounts
        let allRecords = [];
        
        for (const accountId of accounts) {
            const records = await getSMSForDateRange(accountId, yesterday, yesterday);
            if (records.length > 0) {
                console.log(`Account ${accountId}: ${records.length} records`);
                allRecords = allRecords.concat(records);
            }
        }
        
        const data = processRecords(allRecords);
        
        res.json({
            success: true,
            date: yesterday,
            recordCount: allRecords.length,
            data: data,
            accountsQueried: accounts.length,
            message: `Yesterday's SMS data (${yesterday})`
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

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

// =================== SAFE API ENDPOINTS ===================

// Get today's SMS with individual account queries
app.get('/api/vonage/usage/sms/today-safe', authenticateToken, async (req, res) => {
    try {
        const today = new Date().toISOString().slice(0, 10);
        console.log(`\n=== SAFE SMS QUERY FOR TODAY: ${today} ===`);
        
        // Check cache first
        const cacheKey = `safe_sms_${today}`;
        if (dataStore.smsCache[cacheKey] && 
            (Date.now() - dataStore.smsCache[cacheKey].timestamp) < 30 * 60 * 1000) { // 30 min cache
            console.log('Returning cached data');
            return res.json(dataStore.smsCache[cacheKey].data);
        }
        
        // Get list of sub-accounts
        const accounts = await getSubAccountsList();
        console.log(`Found ${accounts.length} accounts to query`);
        
        // SAFETY LIMIT - Only query first 10 accounts for testing
        const accountsToQuery = accounts.slice(0, 10);
        console.log(`SAFETY: Only querying first ${accountsToQuery.length} accounts`);
        
        let allRecords = [];
        let successCount = 0;
        
        // Query each account individually
        for (const account of accountsToQuery) {
            try {
                const records = await getSMSForSingleAccount(account.api_key, today);
                if (records.length > 0) {
                    allRecords = allRecords.concat(records);
                    successCount++;
                }
                
                // Small delay between requests to avoid rate limiting
                await new Promise(resolve => setTimeout(resolve, 500));
            } catch (error) {
                console.error(`Failed to query ${account.api_key}:`, error.message);
            }
        }
        
        // Also query master account
        const masterRecords = await getSMSForSingleAccount(config.vonage.accountId, today);
        if (masterRecords.length > 0) {
            allRecords = allRecords.concat(masterRecords);
        }
        
        console.log(`Total records collected: ${allRecords.length} from ${successCount} accounts`);
        
        // Process the data
        const aggregatedData = processRecords(allRecords);
        
        const result = {
            success: true,
            data: aggregatedData,
            date: today,
            recordCount: allRecords.length,
            accountsQueried: accountsToQuery.length + 1, // +1 for master
            method: 'individual-accounts-safe',
            message: `Today's SMS (${today}) - ${accountsToQuery.length} accounts queried`
        };
        
        // Cache if we got data
        if (allRecords.length > 0) {
            dataStore.smsCache[cacheKey] = {
                data: result,
                timestamp: Date.now()
            };
        }
        
        res.json(result);
        
    } catch (error) {
        console.error('Safe SMS endpoint error:', error);
        res.status(500).json({
            success: false,
            error: error.message,
            data: processRecords([])
        });
    }
});

// Test with yesterday's data (Sept 24 - where your CSV data is from)
app.get('/api/test/yesterday', authenticateToken, async (req, res) => {
    try {
        const testAccount = 'f3fa74ea'; // The account from your CSV
        const yesterday = '2025-09-24'; // Your CSV shows data for this date
        
        console.log(`\n=== TEST: Account ${testAccount} for YESTERDAY ${yesterday} ===`);
        
        const records = await getSMSForSingleAccount(testAccount, yesterday);
        const data = processRecords(records);
        
        res.json({
            success: true,
            account: testAccount,
            date: yesterday,
            recordCount: records.length,
            data: data,
            message: 'Yesterday data test (Sept 24)'
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Test with specific 2-hour window from Vonage support
app.get('/api/test/two-hours', authenticateToken, async (req, res) => {
    try {
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        const headers = {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json'
        };
        
        // EXACT time range from Vonage support that worked
        const body = {
            "account_id": "f3fa74ea",
            "product": "SMS",
            "include_subaccounts": "true",
            "direction": "outbound",
            "date_start": "2025-09-24T05:00:00+0000",
            "date_end": "2025-09-24T07:00:00+0000"
        };
        
        console.log('\n=== TEST: 2-hour window that Vonage confirmed works ===');
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000,
            validateStatus: (status) => status < 500
        });
        
        if (response.data?.records) {
            const data = processRecords(response.data.records);
            res.json({
                success: true,
                recordCount: response.data.records.length,
                data: data,
                message: 'Using exact parameters from Vonage support'
            });
        } else if (response.data?.request_id) {
            // Try quick poll (just 3 attempts)
            for (let i = 1; i <= 3; i++) {
                await new Promise(resolve => setTimeout(resolve, 5000));
                const statusResponse = await axios.get(
                    `https://api.nexmo.com/v2/reports/${response.data.request_id}`,
                    { headers }
                );
                if (statusResponse.data?.status === 'completed') {
                    if (statusResponse.data?.download_url) {
                        const dlResponse = await axios.get(statusResponse.data.download_url, { headers });
                        if (dlResponse.data?.records) {
                            const data = processRecords(dlResponse.data.records);
                            return res.json({
                                success: true,
                                recordCount: dlResponse.data.records.length,
                                data: data
                            });
                        }
                    }
                }
            }
            res.json({
                success: false,
                message: 'Report still processing',
                requestId: response.data.request_id
            });
        } else {
            res.json({
                success: false,
                message: 'No data returned',
                response: response.data
            });
        }
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});=== TEST: Single account ${testAccount} for ${today} ===`);
        
        const records = await getSMSForSingleAccount(testAccount, today);
        const data = processRecords(records);
        
        res.json({
            success: true,
            account: testAccount,
            date: today,
            recordCount: records.length,
            data: data,
            message: 'Single account test'
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// EXACT recreation of Vonage support's working request
app.get('/api/test/exact-vonage', authenticateToken, async (req, res) => {
    try {
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        const headers = {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json'
        };
        
        // EXACT body from Vonage support
        const body = {
            "account_id": "f3fa74ea",
            "product": "SMS",
            "include_subaccounts": "true",
            "direction": "outbound",
            "date_start": "2025-09-24T05:00:00+0000",
            "date_end": "2025-09-24T07:00:00+0000"
            // Not using callback_url - we'll poll instead
        };
        
        console.log('\n=== EXACT VONAGE SUPPORT REQUEST ===');
        console.log('Using master key:', config.vonage.apiKey);
        console.log('Request body:', JSON.stringify(body, null, 2));
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000,
            validateStatus: () => true
        });
        
        console.log('Response status:', response.status);
        
        // If synchronous response with records
        if (response.data?.records && Array.isArray(response.data.records)) {
            const data = processRecords(response.data.records);
            return res.json({
                success: true,
                recordCount: response.data.records.length,
                data: data,
                type: 'synchronous'
            });
        }
        
        // If async response
        if (response.data?.request_id) {
            console.log('Got async request_id:', response.data.request_id);
            
            // Poll for results
            for (let i = 1; i <= 30; i++) {
                await new Promise(resolve => setTimeout(resolve, 5000)); // 5 seconds
                
                const statusUrl = `https://api.nexmo.com/v2/reports/${response.data.request_id}`;
                const statusResponse = await axios.get(statusUrl, { headers });
                
                console.log(`Poll ${i}/30: ${statusResponse.data?.status}`);
                
                if (statusResponse.data?.status === 'completed' || statusResponse.data?.status === 'COMPLETED') {
                    // Download the data
                    if (statusResponse.data?.download_url) {
                        console.log('Downloading from:', statusResponse.data.download_url);
                        const dlResponse = await axios.get(statusResponse.data.download_url, { headers });
                        
                        if (dlResponse.data?.records) {
                            const data = processRecords(dlResponse.data.records);
                            return res.json({
                                success: true,
                                recordCount: dlResponse.data.records.length,
                                data: data,
                                type: 'async-downloaded'
                            });
                        }
                    }
                    
                    if (statusResponse.data?.records) {
                        const data = processRecords(statusResponse.data.records);
                        return res.json({
                            success: true,
                            recordCount: statusResponse.data.records.length,
                            data: data,
                            type: 'async-direct'
                        });
                    }
                }
            }
            
            return res.json({
                success: false,
                message: 'Report still processing after 30 attempts',
                requestId: response.data.request_id
            });
        }
        
        // No records and no request_id
        res.json({
            success: false,
            message: 'No data returned',
            response: response.data,
            status: response.status
        });
        
    } catch (error) {
        console.error('Error:', error.message);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// OLD DISABLED ENDPOINTS - Keeping for backwards compatibility but returning safe error
app.get('/api/vonage/usage/sms', authenticateToken, async (req, res) => {
    // Redirect to safe endpoint
    res.redirect('/api/vonage/usage/sms/today-safe');
});

app.get('/api/vonage/usage/sms/:date', authenticateToken, async (req, res) => {
    res.status(503).json({
        success: false,
        error: 'Use /api/test/single-account for testing',
        data: processRecords([])
    });
});

app.get('/api/vonage/usage/current', authenticateToken, (req, res) => {
    res.redirect('/api/vonage/usage/sms/today-safe');
});

app.get('/api/vonage/dashboard/summary', authenticateToken, async (req, res) => {
    res.redirect('/api/vonage/usage/sms/today-safe');
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
    console.log('✅ VONAGE_API_KEY:', config.vonage.apiKey);
    console.log('✅ VONAGE_ACCOUNT_ID:', config.vonage.accountId);
    
    if (!process.env.VONAGE_API_SECRET) {
        console.error('❌ VONAGE_API_SECRET: NOT SET - Required for API calls');
    } else {
        console.log('✅ VONAGE_API_SECRET: Configured');
    }
    
    const now = new Date();
    console.log('\n=== CURRENT DATE INFO ===');
    console.log(`Server time: ${now.toISOString()}`);
    console.log(`Current month: ${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`);
    
    console.log('\n=== SAFE MODE ACTIVE ===');
    console.log('📌 Limited to 10 accounts per query');
    console.log('📌 Individual account queries only');
    console.log('📌 Today\'s data only');
    console.log('📌 Max 100 seconds polling per account');
    
    console.log('\n========================================\n');
});