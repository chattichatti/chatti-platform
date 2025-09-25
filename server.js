// server.js - Complete Backend Server for Chatti Platform with Vonage Reseller Integration
// Version: Fixed to use include_subaccounts and correct dates

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

// =============== MAIN REPORTS API FUNCTION ===============

async function fetchSMSReports(dateStart, dateEnd) {
    console.log(`\n=== FETCHING SMS REPORTS ===`);
    console.log(`Date range: ${dateStart} to ${dateEnd}`);
    console.log(`Master Account ID: ${config.vonage.accountId}`);
    
    try {
        // Use Basic Auth with master key and secret
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        const headers = {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        };
        
        // Match EXACTLY what Vonage support used
        const body = {
            "account_id": config.vonage.accountId,  // f3fa74ea
            "product": "SMS",
            "include_subaccounts": "true",  // String, not boolean
            "direction": "outbound",
            "date_start": `${dateStart}T00:00:00+0000`,
            "date_end": `${dateEnd}T23:59:59+0000`
        };
        
        console.log('Request body:', JSON.stringify(body, null, 2));
        console.log('Using Basic Auth with API Key:', config.vonage.apiKey);
        
        const url = 'https://api.nexmo.com/v2/reports';
        
        const response = await axios.post(url, body, {
            headers,
            timeout: 30000,
            validateStatus: function (status) {
                return status < 500; // Don't throw on 4xx errors
            }
        });
        
        console.log(`Response status: ${response.status}`);
        
        if (response.status === 200 || response.status === 201 || response.status === 202) {
            // Check if we got immediate results (synchronous)
            if (response.data?.records && Array.isArray(response.data.records)) {
                console.log(`✅ Got synchronous response with ${response.data.records.length} records`);
                
                // Log sample of records for debugging
                if (response.data.records.length > 0) {
                    console.log('Sample record:', JSON.stringify(response.data.records[0], null, 2));
                    
                    // Count records by account_id
                    const accountCounts = {};
                    response.data.records.forEach(r => {
                        const accId = r.account_id || 'unknown';
                        accountCounts[accId] = (accountCounts[accId] || 0) + 1;
                    });
                    console.log('Records by account:', accountCounts);
                }
                
                return response.data.records;
            }
            
            // Check if we got an async request ID - THIS IS WHERE THE DATA IS!
            if (response.data?.request_id) {
                console.log(`⏳ Got async request_id: ${response.data.request_id}`);
                console.log('Polling for async results...');
                
                // Poll for the async results
                return await pollForAsyncResults(response.data.request_id, headers);
            }
            
            // Check if we got an empty result
            if (response.data?.records === null || (Array.isArray(response.data?.records) && response.data.records.length === 0)) {
                console.log('⚠️ API returned empty records array - no data for this period');
                return [];
            }
            
            console.log('⚠️ Unexpected response structure:', JSON.stringify(response.data, null, 2));
            return [];
            
        } else if (response.status === 403) {
            console.error(`❌ 403 Forbidden - Check API permissions`);
            console.error('Error:', response.data);
            return [];
        } else if (response.status === 401) {
            console.error(`❌ 401 Unauthorized - Check API credentials`);
            console.error('Error:', response.data);
            return [];
        } else {
            console.error(`❌ Error response: ${response.status}`);
            console.error('Error data:', response.data);
            return [];
        }
        
    } catch (error) {
        console.error('❌ Reports API error:', error.message);
        if (error.response) {
            console.error('Error response status:', error.response.status);
            console.error('Error response data:', error.response.data);
        }
        return [];
    }
}

// New function to poll for async results - INCREASED TIMEOUT
async function pollForAsyncResults(requestId, headers) {
    const maxAttempts = 90;  // Increased to 15 minutes (90 * 10 seconds)
    const pollInterval = 10000; // Check every 10 seconds
    
    console.log(`Starting to poll for request_id: ${requestId}`);
    console.log(`Will poll up to ${maxAttempts} times (${maxAttempts * pollInterval / 60000} minutes)`);
    
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            console.log(`Poll attempt ${attempt}/${maxAttempts} for request_id: ${requestId}`);
            
            const statusUrl = `https://api.nexmo.com/v2/reports/${requestId}`;
            const response = await axios.get(statusUrl, {
                headers,
                timeout: 10000,
                validateStatus: (status) => status < 500
            });
            
            console.log(`Poll response status: ${response.status}`);
            
            if (response.status === 200) {
                const status = response.data?.status || 'unknown';
                
                // Check if the report is ready
                if (status === 'completed' || status === 'COMPLETED') {
                    console.log('✅ Report completed!');
                    
                    // Check if we have a download URL
                    if (response.data?.download_url) {
                        console.log('📥 Downloading report from:', response.data.download_url);
                        return await downloadReport(response.data.download_url, headers);
                    }
                    
                    // Check if records are directly in the response
                    if (response.data?.records && Array.isArray(response.data.records)) {
                        console.log(`✅ Got ${response.data.records.length} records from async report`);
                        return response.data.records;
                    }
                    
                    console.log('⚠️ Report completed but no records or download_url found');
                    console.log('Response data:', JSON.stringify(response.data, null, 2));
                    return [];
                    
                } else if (status === 'failed' || status === 'FAILED') {
                    console.error('❌ Report generation failed');
                    console.error('Failure details:', response.data);
                    return [];
                    
                } else {
                    console.log(`⏳ Report status: ${status}`);
                    
                    // Log additional progress info if available
                    if (response.data?.records_count !== undefined) {
                        console.log(`   Records being processed: ${response.data.records_count}`);
                    }
                    if (response.data?.progress !== undefined) {
                        console.log(`   Progress: ${response.data.progress}%`);
                    }
                    
                    // Every 10 attempts, log that we're still waiting
                    if (attempt % 10 === 0) {
                        console.log(`⏰ Still processing after ${attempt * pollInterval / 60000} minutes...`);
                        console.log('   Large reports with millions of records can take 10-15 minutes');
                    }
                }
            } else if (response.status === 404) {
                console.error('❌ Request ID not found - may have expired');
                return [];
            }
            
            // Wait before next poll (except on last attempt)
            if (attempt < maxAttempts) {
                await new Promise(resolve => setTimeout(resolve, pollInterval));
            }
            
        } catch (error) {
            console.error(`Poll attempt ${attempt} failed:`, error.message);
            // Continue polling unless it's the last attempt
            if (attempt === maxAttempts) {
                throw error;
            }
        }
    }
    
    console.error(`❌ Polling timeout after ${maxAttempts * pollInterval / 60000} minutes`);
    console.error('The report is still processing. This can happen with very large datasets.');
    console.error('Try querying a smaller date range or specific sub-accounts.');
    return [];
}

// New function to download report from URL
async function downloadReport(downloadUrl, headers) {
    try {
        console.log('📥 Downloading report data...');
        
        const response = await axios.get(downloadUrl, {
            headers,
            timeout: 60000,  // 1 minute timeout for large downloads
            validateStatus: (status) => status < 500
        });
        
        if (response.status === 200) {
            // Check if it's JSON data
            if (response.data?.records && Array.isArray(response.data.records)) {
                console.log(`✅ Downloaded ${response.data.records.length} records`);
                return response.data.records;
            }
            
            // Check if it's CSV data
            if (typeof response.data === 'string' && response.data.includes(',')) {
                console.log('📄 Got CSV data, parsing...');
                // You'd need to parse CSV here - for now just log
                console.log('CSV parsing not implemented - data format:', response.data.substring(0, 200));
                return [];
            }
            
            console.log('⚠️ Unknown data format in download');
            return [];
        }
        
        console.error('❌ Failed to download report:', response.status);
        return [];
        
    } catch (error) {
        console.error('❌ Download error:', error.message);
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

// SAFE function to get SMS for ONE account for TODAY only - WITH POLLING
async function getSMSForSingleAccount(accountId, dateStr) {
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
            "date_start": `${dateStr}T00:00:00+0000`,
            "date_end": `${dateStr}T23:59:59+0000`
            // NO include_subaccounts - just this one account
        };
        
        console.log(`Requesting SMS for account ${accountId} on ${dateStr}`);
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000,
            validateStatus: (status) => status < 500
        });
        
        // If we get immediate results (synchronous)
        if (response.data?.records && Array.isArray(response.data.records)) {
            console.log(`✅ Got ${response.data.records.length} synchronous records for ${accountId}`);
            return response.data.records;
        }
        
        // If async, poll CAREFULLY (single account should be quick)
        if (response.data?.request_id) {
            console.log(`⏳ Got async request for ${accountId}, polling...`);
            return await pollSingleAccountReport(response.data.request_id, headers, accountId);
        }
        
        return [];
    } catch (error) {
        console.error(`Error getting SMS for ${accountId}:`, error.message);
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

// Test with just ONE account (f3fa74ea from CSV)
app.get('/api/test/single-account', authenticateToken, async (req, res) => {
    try {
        const testAccount = 'f3fa74ea'; // The account from your CSV
        const today = new Date().toISOString().slice(0, 10);
        
        console.log(`\n=== TEST: Single account ${testAccount} for ${today} ===`);
        
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

// List all sub-accounts (for debugging)
app.get('/api/vonage/subaccounts/list', authenticateToken, async (req, res) => {
    try {
        const accounts = await getSubAccountsList();
        res.json({
            success: true,
            count: accounts.length,
            accounts: accounts.map(a => ({
                api_key: a.api_key,
                name: a.name || 'Unnamed'
            }))
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Diagnostic endpoint to test the Reports API directly
app.get('/api/test/diagnostic', authenticateToken, async (req, res) => {
    const diagnostics = {
        config: {
            apiKey: config.vonage.apiKey,
            accountId: config.vonage.accountId,
            hasSecret: !!config.vonage.apiSecret,
            secretLength: config.vonage.apiSecret?.length || 0
        },
        tests: {}
    };
    
    // Test 1: Check basic auth
    try {
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        const balanceResponse = await axios.get(`${config.vonage.baseUrl}/account/get-balance`, {
            headers: { 'Authorization': `Basic ${auth}` },
            timeout: 5000
        });
        diagnostics.tests.balance = {
            success: true,
            balance: balanceResponse.data.value,
            status: balanceResponse.status
        };
    } catch (error) {
        diagnostics.tests.balance = {
            success: false,
            error: error.message,
            status: error.response?.status
        };
    }
    
    // Test 2: Try a simple synchronous report for today
    try {
        const today = new Date().toISOString().slice(0, 10);
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        
        const body = {
            "account_id": config.vonage.accountId,
            "product": "SMS",
            "include_subaccounts": "true",
            "direction": "outbound",
            "date_start": `${today}T00:00:00+0000`,
            "date_end": `${today}T23:59:59+0000`
        };
        
        const reportResponse = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json'
            },
            timeout: 10000,
            validateStatus: (status) => true // Accept any status to see the error
        });
        
        diagnostics.tests.reports = {
            success: reportResponse.status === 200 || reportResponse.status === 201 || reportResponse.status === 202,
            status: reportResponse.status,
            hasRequestId: !!reportResponse.data?.request_id,
            hasRecords: !!reportResponse.data?.records,
            recordCount: reportResponse.data?.records?.length || 0,
            responseType: reportResponse.data?.request_id ? 'async' : 'sync',
            data: reportResponse.status >= 400 ? reportResponse.data : undefined
        };
    } catch (error) {
        diagnostics.tests.reports = {
            success: false,
            error: error.message,
            status: error.response?.status,
            data: error.response?.data
        };
    }
    
    res.json(diagnostics);
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
    
    console.log('\n========================================\n');
});