// server.js - Complete Backend Server for Chatti Platform with Vonage SMS Reporting
// Version: Production-ready with per-account breakdown from single API call

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

// CSV line parser that handles quotes and commas
function parseCSVLine(line) {
    const result = [];
    let current = '';
    let inQuotes = false;
    
    for (let i = 0; i < line.length; i++) {
        const char = line[i];
        if (char === '"') {
            inQuotes = !inQuotes;
        } else if (char === ',' && !inQuotes) {
            result.push(current.trim());
            current = '';
        } else {
            current += char;
        }
    }
    result.push(current.trim());
    return result;
}

// Extract and parse CSV from ZIP or plain text
async function extractAndParseCSV(data, isBuffer = false) {
    let csvData = null;
    
    if (isBuffer) {
        const buffer = Buffer.from(data);
        
        // Check if it's a ZIP file (starts with PK)
        if (buffer[0] === 0x50 && buffer[1] === 0x4B) {
            console.log('Extracting CSV from ZIP...');
            const zip = new AdmZip(buffer);
            const zipEntries = zip.getEntries();
            
            for (const entry of zipEntries) {
                if (entry.entryName.endsWith('.csv')) {
                    console.log('Found CSV:', entry.entryName);
                    csvData = zip.readAsText(entry);
                    break;
                }
            }
        }
    } else if (typeof data === 'string') {
        csvData = data;
    }
    
    if (!csvData) return [];
    
    // Parse CSV
    const lines = csvData.split('\n').filter(line => line.trim());
    const headers = parseCSVLine(lines[0]);
    const records = [];
    
    console.log('CSV Headers:', headers.slice(0, 10)); // Log first 10 headers
    
    for (let i = 1; i < lines.length; i++) {
        const values = parseCSVLine(lines[i]);
        const record = {};
        headers.forEach((header, index) => {
            record[header] = values[index] || '';
        });
        records.push(record);
    }
    
    console.log(`Parsed ${records.length} records from CSV`);
    return records;
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

// Currency conversion rates (update these as needed)
const CURRENCY_RATES = {
    EUR_TO_AUD: 1.64  // 1 EUR = 1.64 AUD (approximate, update regularly)
};

function processRecords(records) {
    const aggregated = {
        total: 0,
        outbound: 0,
        inbound: 0,
        byCountry: {},
        bySubAccount: {},
        byDate: {},
        totalCost: 0,        // in EUR
        totalCostAUD: 0      // in AUD
    };
    
    if (!Array.isArray(records)) return aggregated;
    
    for (const record of records) {
        aggregated.total++;
        
        // Handle direction field
        if (record.direction === 'outbound' || record.direction === 'OUTBOUND' || record.type === 'MT') {
            aggregated.outbound++;
        } else {
            aggregated.inbound++;
        }
        
        // Handle cost - Vonage CSV uses 'total_price' field in EUR
        const costEUR = parseFloat(record.total_price || record.price || record.cost || 0);
        const costAUD = costEUR * CURRENCY_RATES.EUR_TO_AUD;
        
        aggregated.totalCost += costEUR;
        aggregated.totalCostAUD += costAUD;
        
        // Handle country - Vonage CSV uses 'country' and 'country_name' fields
        const countryCode = record.country || record.to_country || getCountryFromNumber(record.to);
        const countryName = record.country_name || getCountryName(countryCode);
        
        if (!aggregated.byCountry[countryName]) {
            aggregated.byCountry[countryName] = {
                code: countryCode,
                name: countryName,
                count: 0,
                cost: 0,      // EUR
                costAUD: 0    // AUD
            };
        }
        aggregated.byCountry[countryName].count++;
        aggregated.byCountry[countryName].cost += costEUR;
        aggregated.byCountry[countryName].costAUD += costAUD;
        
        // Handle account ID - Vonage CSV uses 'account_id' field
        const accountId = record.account_id || record.api_key || 'unknown';
        
        if (!aggregated.bySubAccount[accountId]) {
            aggregated.bySubAccount[accountId] = {
                accountId: accountId,
                name: record.account_name || accountId,  // Use account name if available
                count: 0,
                cost: 0,      // EUR
                costAUD: 0    // AUD
            };
        }
        aggregated.bySubAccount[accountId].count++;
        aggregated.bySubAccount[accountId].cost += costEUR;
        aggregated.bySubAccount[accountId].costAUD += costAUD;
        
        // Handle date fields
        const messageDate = record.date_finalized || record.date_received || record.date_start || record.timestamp;
        if (messageDate) {
            const dateKey = messageDate.slice(0, 10);
            if (!aggregated.byDate[dateKey]) {
                aggregated.byDate[dateKey] = { 
                    count: 0, 
                    cost: 0,      // EUR
                    costAUD: 0    // AUD
                };
            }
            aggregated.byDate[dateKey].count++;
            aggregated.byDate[dateKey].cost += costEUR;
            aggregated.byDate[dateKey].costAUD += costAUD;
        }
    }
    
    return aggregated;
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

// =================== MAIN SMS REPORTING ENDPOINTS ===================

// Main endpoint the UI uses for today's data - with per-account breakdown
app.get('/api/vonage/usage/sms/today-safe', authenticateToken, async (req, res) => {
    try {
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        const headers = {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json'
        };
        
        const today = new Date().toISOString().slice(0, 10);
        
        // Check cache
        const cacheKey = `sms_${today}`;
        if (dataStore.smsCache[cacheKey] && 
            (Date.now() - dataStore.smsCache[cacheKey].timestamp) < 30 * 60 * 1000) {
            console.log('Returning cached data for today');
            return res.json(dataStore.smsCache[cacheKey].data);
        }
        
        const body = {
            "account_id": "f3fa74ea",
            "product": "SMS",
            "include_subaccounts": "true",  // This gets ALL sub-accounts in one API call
            "direction": "outbound",
            "date_start": `${today}T00:00:00+0000`,
            "date_end": `${today}T23:59:59+0000`
        };
        
        console.log(`\n=== SMS USAGE REQUEST FOR TODAY: ${today} ===`);
        console.log('Using include_subaccounts to get all data in ONE API call');
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000,
            validateStatus: () => true
        });
        
        if (response.data?.request_id) {
            console.log('Got async request_id, polling...');
            
            // Poll for results
            for (let i = 1; i <= 20; i++) {
                await new Promise(resolve => setTimeout(resolve, 3000));
                
                const statusUrl = `https://api.nexmo.com/v2/reports/${response.data.request_id}`;
                const statusResponse = await axios.get(statusUrl, { headers });
                
                if (statusResponse.data?.request_status === 'SUCCESS') {
                    const downloadUrl = statusResponse.data?._links?.download_report?.href;
                    
                    if (downloadUrl) {
                        console.log(`Downloading ${statusResponse.data.items_count} records...`);
                        
                        const dlResponse = await axios.get(downloadUrl, { 
                            headers, 
                            timeout: 60000,
                            responseType: 'arraybuffer'
                        });
                        
                        const records = await extractAndParseCSV(dlResponse.data, true);
                        const data = processRecords(records);
                        
                        // Create per-account summary with more detail
                        const perAccountDetail = {};
                        const accountNames = {}; // Store account names
                        
                        for (const record of records) {
                            const accountId = record.account_id || record.api_key || 'unknown';
                            const accountName = record.account_name || '';
                            
                            if (accountName && !accountNames[accountId]) {
                                accountNames[accountId] = accountName;
                            }
                            
                            if (!perAccountDetail[accountId]) {
                                perAccountDetail[accountId] = {
                                    accountId: accountId,
                                    name: accountName || accountId,
                                    count: 0,
                                    cost: 0,      // EUR
                                    costAUD: 0,   // AUD
                                    countries: new Set()
                                };
                            }
                            
                            const costEUR = parseFloat(record.total_price || 0);
                            const costAUD = costEUR * CURRENCY_RATES.EUR_TO_AUD;
                            
                            perAccountDetail[accountId].count++;
                            perAccountDetail[accountId].cost += costEUR;
                            perAccountDetail[accountId].costAUD += costAUD;
                            perAccountDetail[accountId].countries.add(
                                record.country_name || record.country || 'Unknown'
                            );
                            
                            // Update name if we found it
                            if (accountName && !perAccountDetail[accountId].name) {
                                perAccountDetail[accountId].name = accountName;
                            }
                        }
                        
                        // Convert sets to arrays and add account names
                        Object.keys(perAccountDetail).forEach(key => {
                            perAccountDetail[key].countries = Array.from(perAccountDetail[key].countries);
                            if (accountNames[key]) {
                                perAccountDetail[key].name = accountNames[key];
                            }
                        });
                        
                        // Count unique accounts with activity
                        const activeAccounts = Object.keys(perAccountDetail).length;
                        
                        const result = {
                            success: true,
                            data: data,
                            perAccount: perAccountDetail,  // Detailed per-account breakdown
                            date: today,
                            recordCount: records.length,
                            accountsQueried: 1,  // We made only 1 API call
                            activeAccounts: activeAccounts,  // Number of accounts with SMS today
                            method: 'vonage-reports-api-with-subaccounts',
                            currencyRate: CURRENCY_RATES.EUR_TO_AUD
                        };
                        
                        // Cache the result
                        dataStore.smsCache[cacheKey] = {
                            data: result,
                            timestamp: Date.now()
                        };
                        
                        return res.json(result);
                    }
                }
            }
        }
        
        res.json({
            success: false,
            message: 'No SMS data for today yet',
            data: processRecords([]),
            perAccount: {},
            date: today
        });
        
    } catch (error) {
        console.error('SMS usage error:', error);
        res.status(500).json({
            success: false,
            error: error.message,
            data: processRecords([]),
            perAccount: {}
        });
    }
});

// Get SMS for specific date
app.get('/api/vonage/usage/sms/:date', authenticateToken, async (req, res) => {
    try {
        const { date } = req.params;
        
        if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid date format. Use YYYY-MM-DD'
            });
        }
        
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        const headers = {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json'
        };
        
        const body = {
            "account_id": "f3fa74ea",
            "product": "SMS",
            "include_subaccounts": "true",
            "direction": "outbound",
            "date_start": `${date}T00:00:00+0000`,
            "date_end": `${date}T23:59:59+0000`
        };
        
        console.log(`\n=== SMS USAGE REQUEST FOR ${date} ===`);
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000
        });
        
        if (response.data?.request_id) {
            for (let i = 1; i <= 10; i++) {
                await new Promise(resolve => setTimeout(resolve, 2000));
                
                const statusUrl = `https://api.nexmo.com/v2/reports/${response.data.request_id}`;
                const statusResponse = await axios.get(statusUrl, { headers });
                
                if (statusResponse.data?.request_status === 'SUCCESS') {
                    const downloadUrl = statusResponse.data?._links?.download_report?.href;
                    
                    if (downloadUrl) {
                        const dlResponse = await axios.get(downloadUrl, { 
                            headers,
                            responseType: 'arraybuffer'
                        });
                        
                        const records = await extractAndParseCSV(dlResponse.data, true);
                        const data = processRecords(records);
                        
                        return res.json({
                            success: true,
                            data: data,
                            date: date,
                            recordCount: records.length
                        });
                    }
                }
            }
        }
        
        res.json({
            success: false,
            message: `No data for ${date}`,
            data: processRecords([]),
            date: date
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            data: processRecords([])
        });
    }
});

// =================== MULTI-ACCOUNT REPORT ENDPOINTS ===================

// Get list of all sub-accounts with their API keys
app.get('/api/vonage/subaccounts/list-with-keys', authenticateToken, async (req, res) => {
    try {
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        const url = `https://api.nexmo.com/accounts/${config.vonage.accountId}/subaccounts`;
        
        console.log('\n=== FETCHING SUB-ACCOUNTS LIST ===');
        
        const response = await axios.get(url, {
            headers: { 'Authorization': `Basic ${auth}` },
            timeout: 10000
        });
        
        let accounts = [];
        if (response.data?._embedded?.subaccounts) {
            accounts = response.data._embedded.subaccounts.map(acc => ({
                api_key: acc.api_key,
                name: acc.name || `Account ${acc.api_key}`,
                balance: acc.balance,
                created_at: acc.created_at
            }));
        }
        
        // Add the master account at the beginning
        accounts.unshift({
            api_key: config.vonage.accountId,
            name: 'Master Account',
            balance: 0,
            is_master: true
        });
        
        console.log(`Found ${accounts.length} accounts (including master)`);
        
        res.json({
            success: true,
            count: accounts.length,
            accounts: accounts
        });
        
    } catch (error) {
        console.error('Error fetching sub-accounts:', error);
        res.json({
            success: false,
            error: error.message,
            accounts: []
        });
    }
});

// Query multiple accounts individually and compile results
app.get('/api/vonage/usage/sms/multi-account-today', authenticateToken, async (req, res) => {
    try {
        const today = new Date().toISOString().slice(0, 10);
        
        // Check cache first
        const cacheKey = `multi_account_${today}`;
        if (dataStore.smsCache[cacheKey] && 
            (Date.now() - dataStore.smsCache[cacheKey].timestamp) < 60 * 60 * 1000) {
            console.log('Returning cached multi-account data');
            return res.json(dataStore.smsCache[cacheKey].data);
        }
        
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        const headers = {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json'
        };
        
        console.log(`\n=== MULTI-ACCOUNT SMS REPORT FOR ${today} ===`);
        
        // First get list of all sub-accounts
        const accountsUrl = `https://api.nexmo.com/accounts/${config.vonage.accountId}/subaccounts`;
        const accountsResponse = await axios.get(accountsUrl, {
            headers: { 'Authorization': `Basic ${auth}` },
            timeout: 10000
        });
        
        let accounts = [];
        if (accountsResponse.data?._embedded?.subaccounts) {
            accounts = accountsResponse.data._embedded.subaccounts;
        }
        
        // Add the master account
        accounts.unshift({
            api_key: config.vonage.accountId,
            name: 'Master Account'
        });
        
        // Limit to first 10 accounts for safety (remove this limit when ready)
        const limitedAccounts = accounts.slice(0, 10);
        console.log(`Processing ${limitedAccounts.length} accounts (limited for safety)`);
        
        // Store all results
        const accountResults = [];
        let totalRecords = 0;
        let totalCostEUR = 0;
        let failedAccounts = [];
        const allCountries = new Set();
        
        // Process accounts sequentially to avoid rate limiting
        for (const account of limitedAccounts) {
            try {
                console.log(`\nQuerying account: ${account.api_key} (${account.name || 'Unnamed'})`);
                
                const body = {
                    "account_id": account.api_key,
                    "product": "SMS",
                    "direction": "outbound",
                    "date_start": `${today}T00:00:00+0000`,
                    "date_end": `${today}T23:59:59+0000`
                    // Note: NOT using include_subaccounts here
                };
                
                const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
                    headers,
                    timeout: 30000
                });
                
                let accountData = null;
                
                // Handle synchronous response (small datasets)
                if (response.data?.data) {
                    const records = response.data.data;
                    accountData = processAccountRecords(records, account);
                    console.log(`✓ ${account.api_key}: ${records.length} SMS (sync response)`);
                }
                // Handle asynchronous response (larger datasets)
                else if (response.data?.request_id) {
                    console.log(`  Async report ${response.data.request_id}, polling...`);
                    
                    // Poll for results (max 10 attempts)
                    for (let attempt = 1; attempt <= 10; attempt++) {
                        await new Promise(resolve => setTimeout(resolve, 2000));
                        
                        const statusUrl = `https://api.nexmo.com/v2/reports/${response.data.request_id}`;
                        const statusResponse = await axios.get(statusUrl, { headers });
                        
                        if (statusResponse.data?.request_status === 'SUCCESS') {
                            const downloadUrl = statusResponse.data?._links?.download_report?.href;
                            
                            if (downloadUrl) {
                                const dlResponse = await axios.get(downloadUrl, {
                                    headers,
                                    timeout: 30000,
                                    responseType: 'arraybuffer'
                                });
                                
                                const records = await extractAndParseCSV(dlResponse.data, true);
                                accountData = processAccountRecords(records, account);
                                console.log(`✓ ${account.api_key}: ${records.length} SMS (async response)`);
                                break;
                            }
                        }
                        
                        if (attempt === 10) {
                            console.log(`✗ ${account.api_key}: Report timeout`);
                        }
                    }
                }
                
                // Add to results if we got data
                if (accountData && accountData.count > 0) {
                    accountResults.push({
                        accountId: account.api_key,
                        accountName: account.name || 'Unnamed',
                        ...accountData
                    });
                    
                    totalRecords += accountData.count;
                    totalCostEUR += accountData.costEUR;
                    accountData.countries.forEach(c => allCountries.add(c));
                } else {
                    console.log(`○ ${account.api_key}: No SMS today`);
                }
                
                // Small delay between accounts to avoid rate limiting
                await new Promise(resolve => setTimeout(resolve, 500));
                
            } catch (error) {
                console.error(`✗ ${account.api_key}: Error - ${error.message}`);
                failedAccounts.push({
                    accountId: account.api_key,
                    error: error.message
                });
            }
        }
        
        console.log('\n=== MULTI-ACCOUNT SUMMARY ===');
        console.log(`Total accounts processed: ${limitedAccounts.length}`);
        console.log(`Accounts with SMS: ${accountResults.length}`);
        console.log(`Failed accounts: ${failedAccounts.length}`);
        console.log(`Total SMS: ${totalRecords}`);
        console.log(`Total cost: €${totalCostEUR.toFixed(2)}`);
        
        // Compile final result
        const result = {
            success: true,
            date: today,
            accountsQueried: limitedAccounts.length,
            accountsWithData: accountResults.length,
            failedAccounts: failedAccounts.length,
            accounts: accountResults,
            summary: {
                totalSMS: totalRecords,
                totalCostEUR: totalCostEUR,
                totalCostAUD: totalCostEUR * CURRENCY_RATES.EUR_TO_AUD,
                uniqueCountries: Array.from(allCountries),
                countriesReached: allCountries.size
            },
            failedAccountsList: failedAccounts,
            note: 'Limited to 10 accounts for safety. Remove limit when ready for production.'
        };
        
        // Cache the result
        dataStore.smsCache[cacheKey] = {
            data: result,
            timestamp: Date.now()
        };
        
        res.json(result);
        
    } catch (error) {
        console.error('Multi-account query error:', error);
        res.status(500).json({
            success: false,
            error: error.message,
            accounts: []
        });
    }
});

// Helper function to process records for a single account
function processAccountRecords(records, accountInfo) {
    if (!records || records.length === 0) {
        return {
            count: 0,
            costEUR: 0,
            costAUD: 0,
            countries: [],
            byCountry: {}
        };
    }
    
    const countryStats = {};
    let totalCostEUR = 0;
    let totalCount = 0;
    
    for (const record of records) {
        totalCount++;
        
        const costEUR = parseFloat(record.total_price || record.price || record.cost || 0);
        totalCostEUR += costEUR;
        
        const country = record.country_name || record.country || 
                       getCountryName(record.to_country || getCountryFromNumber(record.to));
        
        if (!countryStats[country]) {
            countryStats[country] = {
                count: 0,
                costEUR: 0
            };
        }
        
        countryStats[country].count++;
        countryStats[country].costEUR += costEUR;
    }
    
    return {
        count: totalCount,
        costEUR: totalCostEUR,
        costAUD: totalCostEUR * CURRENCY_RATES.EUR_TO_AUD,
        countries: Object.keys(countryStats),
        byCountry: countryStats
    };
}

// Test endpoint for a single account
app.get('/api/test/single-account/:accountId', authenticateToken, async (req, res) => {
    try {
        const { accountId } = req.params;
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        const headers = {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json'
        };
        
        const today = new Date().toISOString().slice(0, 10);
        
        const body = {
            "account_id": accountId,
            "product": "SMS",
            "direction": "outbound",
            "date_start": `${today}T00:00:00+0000`,
            "date_end": `${today}T23:59:59+0000`
        };
        
        console.log(`\n=== TESTING SINGLE ACCOUNT: ${accountId} ===`);
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000
        });
        
        res.json({
            success: true,
            accountId: accountId,
            response: response.data
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            details: error.response?.data
        });
    }
});

// List sub-accounts (for reference only - we don't query them individually)
app.get('/api/vonage/subaccounts/list', authenticateToken, async (req, res) => {
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
        
        res.json({
            success: true,
            count: accounts.length,
            accounts: accounts.map(a => ({
                api_key: a.api_key,
                name: a.name || 'Unnamed',
                balance: a.balance
            })),
            note: 'These accounts are all included when using include_subaccounts=true'
        });
        
    } catch (error) {
        res.json({
            success: false,
            error: error.message,
            count: 0,
            accounts: []
        });
    }
});

// Test endpoint
app.get('/api/test/exact-vonage', authenticateToken, async (req, res) => {
    try {
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        const headers = {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json'
        };
        
        const body = {
            "account_id": "f3fa74ea",
            "product": "SMS",
            "include_subaccounts": "true",
            "direction": "outbound",
            "date_start": "2025-09-24T05:00:00+0000",
            "date_end": "2025-09-24T07:00:00+0000"
        };
        
        console.log('\n=== EXACT VONAGE SUPPORT REQUEST ===');
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000
        });
        
        if (response.data?.request_id) {
            for (let i = 1; i <= 30; i++) {
                await new Promise(resolve => setTimeout(resolve, 5000));
                
                const statusUrl = `https://api.nexmo.com/v2/reports/${response.data.request_id}`;
                const statusResponse = await axios.get(statusUrl, { headers });
                
                if (statusResponse.data?.request_status === 'SUCCESS') {
                    const downloadUrl = statusResponse.data?._links?.download_report?.href;
                    
                    if (downloadUrl) {
                        const dlResponse = await axios.get(downloadUrl, { 
                            headers,
                            responseType: 'arraybuffer'
                        });
                        
                        const records = await extractAndParseCSV(dlResponse.data, true);
                        const data = processRecords(records);
                        
                        return res.json({
                            success: true,
                            recordCount: records.length,
                            data: data,
                            type: 'zip-csv-parsed'
                        });
                    }
                }
            }
            
            return res.json({
                success: false,
                message: 'Report still processing',
                requestId: response.data.request_id
            });
        }
        
        res.json({
            success: false,
            message: 'No data returned'
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Redirect old endpoints
app.get('/api/vonage/usage/sms', authenticateToken, (req, res) => {
    res.redirect('/api/vonage/usage/sms/today-safe');
});

app.get('/api/vonage/usage/current', authenticateToken, (req, res) => {
    res.redirect('/api/vonage/usage/sms/today-safe');
});

app.get('/api/vonage/dashboard/summary', authenticateToken, (req, res) => {
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
    console.log('✅ VONAGE_API_KEY:', config.vonage.apiKey);
    console.log('✅ VONAGE_API_SECRET:', config.vonage.apiSecret ? 'Set' : 'NOT SET');
    console.log('✅ VONAGE_ACCOUNT_ID:', config.vonage.accountId);
    
    console.log('\n=== FEATURES ===');
    console.log('✅ ZIP file extraction');
    console.log('✅ CSV parsing with per-account breakdown');
    console.log('✅ EUR to AUD currency conversion');
    console.log('✅ 30-minute caching');
    console.log('✅ Safe polling (max 20 attempts)');
    console.log('✅ Single API call for all sub-accounts');
    
    console.log('\n========================================\n');
});