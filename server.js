// server.js - Complete Backend Server with Proper Sub-Account Parsing
// Version: Uses single API call and parses CSV for sub-account breakdown

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
    
    console.log('CSV Headers:', headers);
    
    for (let i = 1; i < lines.length; i++) {
        const values = parseCSVLine(lines[i]);
        const record = {};
        headers.forEach((header, index) => {
            record[header] = values[index] || '';
        });
        records.push(record);
    }
    
    console.log(`Parsed ${records.length} records from CSV`);
    
    // Log sample record to see available fields
    if (records.length > 0) {
        console.log('Sample record fields:', Object.keys(records[0]));
        console.log('Looking for account identifiers...');
        
        // Check various possible field names for account identification
        const possibleFields = ['account_id', 'api_key', 'subaccount_id', 'subaccount_key', 'client_ref', 'custom_id'];
        for (const field of possibleFields) {
            if (records[0][field]) {
                console.log(`Found field "${field}" with value: ${records[0][field]}`);
            }
        }
    }
    
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

function processRecordsWithSubAccounts(records) {
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
    
    // Per-account details
    const perAccountDetail = {};
    
    if (!Array.isArray(records)) return { aggregated, perAccountDetail };
    
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
        
        // Handle country
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
        
        // IMPORTANT: Find the correct account identifier in the CSV
        // Try multiple possible field names that Vonage might use
        let accountId = record.account_id || 
                       record.api_key || 
                       record.subaccount_id || 
                       record.subaccount_key || 
                       record.client_ref || 
                       record.custom_id ||
                       record.account ||
                       'unknown';
        
        // Also check for message_id pattern that might contain account info
        if (accountId === 'unknown' && record.message_id) {
            // Some systems encode account ID in message_id
            const parts = record.message_id.split('-');
            if (parts.length > 1) {
                accountId = parts[0]; // First part might be account ID
            }
        }
        
        // Build aggregated by sub-account
        if (!aggregated.bySubAccount[accountId]) {
            aggregated.bySubAccount[accountId] = {
                accountId: accountId,
                count: 0,
                cost: 0,      // EUR
                costAUD: 0    // AUD
            };
        }
        aggregated.bySubAccount[accountId].count++;
        aggregated.bySubAccount[accountId].cost += costEUR;
        aggregated.bySubAccount[accountId].costAUD += costAUD;
        
        // Build detailed per-account data
        if (!perAccountDetail[accountId]) {
            perAccountDetail[accountId] = {
                accountId: accountId,
                name: record.account_name || accountId,
                count: 0,
                cost: 0,      // EUR
                costAUD: 0,   // AUD
                countries: new Set(),
                byCountry: {}
            };
        }
        
        perAccountDetail[accountId].count++;
        perAccountDetail[accountId].cost += costEUR;
        perAccountDetail[accountId].costAUD += costAUD;
        perAccountDetail[accountId].countries.add(countryName);
        
        // Track per-country stats for this account
        if (!perAccountDetail[accountId].byCountry[countryName]) {
            perAccountDetail[accountId].byCountry[countryName] = {
                count: 0,
                cost: 0
            };
        }
        perAccountDetail[accountId].byCountry[countryName].count++;
        perAccountDetail[accountId].byCountry[countryName].cost += costEUR;
        
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
    
    // Convert sets to arrays
    Object.keys(perAccountDetail).forEach(key => {
        perAccountDetail[key].countries = Array.from(perAccountDetail[key].countries);
    });
    
    return { aggregated, perAccountDetail };
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

// =================== MAIN SMS REPORTING ENDPOINT ===================

// Main endpoint - Gets all data in one call and parses for sub-accounts
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
            "include_subaccounts": "true",  // Gets ALL sub-accounts in one call
            "direction": "outbound",
            "date_start": `${today}T00:00:00+0000`,
            "date_end": `${today}T23:59:59+0000`
        };
        
        console.log(`\n=== SMS USAGE REQUEST FOR TODAY: ${today} ===`);
        console.log('Getting all sub-accounts data in ONE API call');
        
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
                        const { aggregated, perAccountDetail } = processRecordsWithSubAccounts(records);
                        
                        // Count unique accounts
                        const activeAccounts = Object.keys(perAccountDetail).length;
                        
                        console.log(`Found ${activeAccounts} unique account IDs in the data`);
                        
                        const result = {
                            success: true,
                            data: aggregated,
                            perAccount: perAccountDetail,
                            date: today,
                            recordCount: records.length,
                            activeAccounts: activeAccounts,
                            method: 'single-api-call-with-parsing',
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
            data: processRecordsWithSubAccounts([]).aggregated,
            perAccount: {},
            date: today
        });
        
    } catch (error) {
        console.error('SMS usage error:', error);
        res.status(500).json({
            success: false,
            error: error.message,
            data: processRecordsWithSubAccounts([]).aggregated,
            perAccount: {}
        });
    }
});

// Debug endpoint to check CSV fields
app.get('/api/debug/csv-fields', authenticateToken, async (req, res) => {
    try {
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        const headers = {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json'
        };
        
        const today = new Date().toISOString().slice(0, 10);
        
        const body = {
            "account_id": "f3fa74ea",
            "product": "SMS",
            "include_subaccounts": "true",
            "direction": "outbound",
            "date_start": `${today}T00:00:00+0000`,
            "date_end": `${today}T23:59:59+0000`
        };
        
        console.log('\n=== CSV FIELD DEBUG ===');
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000
        });
        
        if (response.data?.request_id) {
            for (let i = 1; i <= 20; i++) {
                await new Promise(resolve => setTimeout(resolve, 3000));
                
                const statusUrl = `https://api.nexmo.com/v2/reports/${response.data.request_id}`;
                const statusResponse = await axios.get(statusUrl, { headers });
                
                if (statusResponse.data?.request_status === 'SUCCESS') {
                    const downloadUrl = statusResponse.data?._links?.download_report?.href;
                    
                    if (downloadUrl) {
                        const dlResponse = await axios.get(downloadUrl, {
                            headers,
                            timeout: 60000,
                            responseType: 'arraybuffer'
                        });
                        
                        const records = await extractAndParseCSV(dlResponse.data, true);
                        
                        if (records.length > 0) {
                            // Get all unique values for potential account fields
                            const accountFields = {};
                            const fieldNames = Object.keys(records[0]);
                            
                            // Check each field that might contain account IDs
                            for (const field of fieldNames) {
                                if (field.toLowerCase().includes('account') || 
                                    field.toLowerCase().includes('api') || 
                                    field.toLowerCase().includes('key') ||
                                    field.toLowerCase().includes('client') ||
                                    field.toLowerCase().includes('ref')) {
                                    
                                    const uniqueValues = new Set();
                                    for (const record of records.slice(0, 100)) { // Check first 100 records
                                        if (record[field]) {
                                            uniqueValues.add(record[field]);
                                        }
                                    }
                                    
                                    if (uniqueValues.size > 0) {
                                        accountFields[field] = Array.from(uniqueValues).slice(0, 5); // Show first 5 unique values
                                    }
                                }
                            }
                            
                            return res.json({
                                success: true,
                                totalRecords: records.length,
                                allFields: fieldNames,
                                potentialAccountFields: accountFields,
                                sampleRecord: records[0],
                                firstThreeRecords: records.slice(0, 3)
                            });
                        }
                    }
                }
            }
        }
        
        res.json({
            success: false,
            message: 'Could not get CSV fields'
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
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
                        const { aggregated, perAccountDetail } = processRecordsWithSubAccounts(records);
                        
                        return res.json({
                            success: true,
                            data: aggregated,
                            perAccount: perAccountDetail,
                            date: date,
                            recordCount: records.length,
                            activeAccounts: Object.keys(perAccountDetail).length
                        });
                    }
                }
            }
        }
        
        res.json({
            success: false,
            message: `No data for ${date}`,
            data: processRecordsWithSubAccounts([]).aggregated,
            date: date
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            data: processRecordsWithSubAccounts([]).aggregated
        });
    }
});

// List sub-accounts
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
            }))
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

// Redirect old endpoints
app.get('/api/vonage/usage/sms', authenticateToken, (req, res) => {
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
    
    console.log('\n=== FEATURES ===`);
    console.log('✅ ZIP file extraction');
    console.log('✅ CSV parsing with sub-account detection');
    console.log('✅ EUR to AUD currency conversion');
    console.log('✅ 30-minute caching');
    console.log('✅ Single API call for all data');
    
    console.log('\n========================================\n');
});