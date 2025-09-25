// server.js - Complete Backend Server for Chatti Platform
// Version: Production-ready with all features

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

// Simple user store (in production, use a database)
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

// Store for caching data
let dataStore = {
    smsCache: {}
};

// Currency conversion rates
const CURRENCY_RATES = {
    EUR_TO_AUD: 1.64  // Update this regularly or fetch from an API
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
    if (cleaned.startsWith('33')) return 'FR';
    if (cleaned.startsWith('49')) return 'DE';
    
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
        'FR': 'France',
        'DE': 'Germany',
        'Other': 'Other Countries',
        'Unknown': 'Unknown'
    };
    return countries[code] || code;
}

// Parse CSV line handling quotes and commas
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

// Extract and parse CSV from ZIP file
async function extractAndParseCSV(data, isBuffer = false) {
    let csvData = null;
    
    if (isBuffer) {
        const buffer = Buffer.from(data);
        
        // Check if it's a ZIP file (starts with PK bytes)
        if (buffer[0] === 0x50 && buffer[1] === 0x4B) {
            console.log('Extracting CSV from ZIP file...');
            const zip = new AdmZip(buffer);
            const zipEntries = zip.getEntries();
            
            // Find the CSV file in the ZIP
            for (const entry of zipEntries) {
                if (entry.entryName.endsWith('.csv')) {
                    console.log('Found CSV file:', entry.entryName);
                    csvData = zip.readAsText(entry);
                    break;
                }
            }
            
            if (!csvData) {
                console.error('No CSV file found in ZIP archive');
                return [];
            }
        } else {
            // Not a ZIP, try to parse as plain text
            csvData = buffer.toString('utf8');
        }
    } else if (typeof data === 'string') {
        csvData = data;
    }
    
    if (!csvData) {
        console.error('No CSV data to parse');
        return [];
    }
    
    // Parse CSV into records
    const lines = csvData.split('\n').filter(line => line.trim());
    if (lines.length === 0) {
        console.error('CSV file is empty');
        return [];
    }
    
    const headers = parseCSVLine(lines[0]);
    const records = [];
    
    console.log(`CSV has ${headers.length} columns and ${lines.length - 1} data rows`);
    console.log('CSV Headers:', headers);
    
    // Parse each data row
    for (let i = 1; i < lines.length; i++) {
        const values = parseCSVLine(lines[i]);
        if (values.length !== headers.length) {
            console.warn(`Row ${i} has ${values.length} values but expected ${headers.length}`);
            continue;
        }
        
        const record = {};
        headers.forEach((header, index) => {
            record[header] = values[index] || '';
        });
        records.push(record);
    }
    
    console.log(`Successfully parsed ${records.length} records from CSV`);
    return records;
}

// Process SMS records and aggregate data
function processRecords(records) {
    const aggregated = {
        total: 0,
        outbound: 0,
        inbound: 0,
        byCountry: {},
        bySubAccount: {},
        byDate: {},
        totalCost: 0,      // EUR
        totalCostAUD: 0    // AUD
    };
    
    const perAccountDetail = {};
    
    if (!Array.isArray(records) || records.length === 0) {
        return { aggregated, perAccountDetail };
    }
    
    // Process each record
    for (const record of records) {
        aggregated.total++;
        
        // Determine direction
        const direction = record.direction || record.type || '';
        if (direction.toLowerCase().includes('out') || direction === 'MT') {
            aggregated.outbound++;
        } else if (direction.toLowerCase().includes('in') || direction === 'MO') {
            aggregated.inbound++;
        }
        
        // Calculate cost (Vonage uses EUR)
        const costEUR = parseFloat(record.total_price || record.price || record.cost || 0);
        const costAUD = costEUR * CURRENCY_RATES.EUR_TO_AUD;
        
        aggregated.totalCost += costEUR;
        aggregated.totalCostAUD += costAUD;
        
        // Determine country
        const countryCode = record.country || record.to_country || getCountryFromNumber(record.to || '');
        const countryName = record.country_name || getCountryName(countryCode);
        
        if (!aggregated.byCountry[countryName]) {
            aggregated.byCountry[countryName] = {
                code: countryCode,
                name: countryName,
                count: 0,
                cost: 0,
                costAUD: 0
            };
        }
        aggregated.byCountry[countryName].count++;
        aggregated.byCountry[countryName].cost += costEUR;
        aggregated.byCountry[countryName].costAUD += costAUD;
        
        // Find account ID - try multiple possible field names
        let accountId = record.account_id || 
                       record.api_key || 
                       record.subaccount_id || 
                       record.subaccount_key || 
                       record.subaccount ||
                       record.account ||
                       record.client_ref || 
                       record.custom_id ||
                       record.sender_id ||
                       record.from_account ||
                       'unknown';
        
        // Build sub-account aggregation
        if (!aggregated.bySubAccount[accountId]) {
            aggregated.bySubAccount[accountId] = {
                accountId: accountId,
                count: 0,
                cost: 0,
                costAUD: 0
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
                cost: 0,
                costAUD: 0,
                countries: new Set(),
                byCountry: {}
            };
        }
        
        perAccountDetail[accountId].count++;
        perAccountDetail[accountId].cost += costEUR;
        perAccountDetail[accountId].costAUD += costAUD;
        perAccountDetail[accountId].countries.add(countryName);
        
        if (!perAccountDetail[accountId].byCountry[countryName]) {
            perAccountDetail[accountId].byCountry[countryName] = {
                count: 0,
                cost: 0
            };
        }
        perAccountDetail[accountId].byCountry[countryName].count++;
        perAccountDetail[accountId].byCountry[countryName].cost += costEUR;
        
        // Process date
        const messageDate = record.date_finalized || record.date_received || 
                          record.date_start || record.timestamp || record.date;
        if (messageDate) {
            const dateKey = messageDate.slice(0, 10);
            if (!aggregated.byDate[dateKey]) {
                aggregated.byDate[dateKey] = { 
                    count: 0, 
                    cost: 0,
                    costAUD: 0
                };
            }
            aggregated.byDate[dateKey].count++;
            aggregated.byDate[dateKey].cost += costEUR;
            aggregated.byDate[dateKey].costAUD += costAUD;
        }
    }
    
    // Convert Sets to Arrays
    Object.keys(perAccountDetail).forEach(key => {
        perAccountDetail[key].countries = Array.from(perAccountDetail[key].countries);
    });
    
    return { aggregated, perAccountDetail };
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

// =================== ROUTES ===================

// Serve index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Chatti Platform API is running',
        timestamp: new Date().toISOString()
    });
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, passHash } = req.body;
        
        const user = users.find(u => u.email === email);
        
        if (!user || passHash !== user.passwordHash) {
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
        console.error('Vonage test error:', error.message);
        res.json({ 
            success: false, 
            error: error.message 
        });
    }
});

// Main SMS usage endpoint - gets all sub-accounts data in one call
app.get('/api/vonage/usage/sms/today-safe', authenticateToken, async (req, res) => {
    try {
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        const headers = {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json'
        };
        
        const today = new Date().toISOString().slice(0, 10);
        
        // Check cache (30 minute cache)
        const cacheKey = `sms_${today}`;
        if (dataStore.smsCache[cacheKey] && 
            (Date.now() - dataStore.smsCache[cacheKey].timestamp) < 30 * 60 * 1000) {
            console.log('Returning cached data for today');
            return res.json(dataStore.smsCache[cacheKey].data);
        }
        
        // Request body for Vonage Reports API
        const body = {
            "account_id": "f3fa74ea",
            "product": "SMS",
            "include_subaccounts": "true",  // This gets ALL sub-accounts in one call
            "direction": "outbound",
            "date_start": `${today}T00:00:00+0000`,
            "date_end": `${today}T23:59:59+0000`
        };
        
        console.log(`\n=== SMS USAGE REQUEST FOR ${today} ===`);
        console.log('Account:', body.account_id);
        console.log('Include subaccounts:', body.include_subaccounts);
        
        // Create async report
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000,
            validateStatus: () => true
        });
        
        if (!response.data?.request_id) {
            console.error('No request_id received from Vonage');
            return res.json({
                success: false,
                message: 'Failed to create report',
                data: processRecords([]).aggregated,
                perAccount: {},
                date: today
            });
        }
        
        console.log('Report request created, ID:', response.data.request_id);
        console.log('Polling for results...');
        
        // Poll for report completion
        let reportData = null;
        for (let attempt = 1; attempt <= 20; attempt++) {
            await new Promise(resolve => setTimeout(resolve, 3000)); // Wait 3 seconds
            
            const statusUrl = `https://api.nexmo.com/v2/reports/${response.data.request_id}`;
            const statusResponse = await axios.get(statusUrl, { headers });
            
            console.log(`Attempt ${attempt}: Status = ${statusResponse.data?.request_status}`);
            
            if (statusResponse.data?.request_status === 'SUCCESS') {
                const downloadUrl = statusResponse.data?._links?.download_report?.href;
                
                if (downloadUrl) {
                    console.log('Report ready, downloading...');
                    console.log('Items count:', statusResponse.data.items_count);
                    
                    // Download the report (comes as ZIP)
                    const dlResponse = await axios.get(downloadUrl, { 
                        headers, 
                        timeout: 60000,
                        responseType: 'arraybuffer'
                    });
                    
                    // Extract and parse CSV from ZIP
                    const records = await extractAndParseCSV(dlResponse.data, true);
                    reportData = processRecords(records);
                    
                    console.log(`Processed ${records.length} SMS records`);
                    console.log(`Found ${Object.keys(reportData.perAccountDetail).length} unique accounts`);
                    break;
                }
            } else if (statusResponse.data?.request_status === 'FAILED') {
                console.error('Report generation failed');
                break;
            }
        }
        
        if (!reportData) {
            console.log('Report polling timed out or failed');
            return res.json({
                success: false,
                message: 'Report generation timed out',
                data: processRecords([]).aggregated,
                perAccount: {},
                date: today
            });
        }
        
        // Prepare response
        const result = {
            success: true,
            data: reportData.aggregated,
            perAccount: reportData.perAccountDetail,
            date: today,
            recordCount: reportData.aggregated.total,
            activeAccounts: Object.keys(reportData.perAccountDetail).length,
            method: 'single-api-call',
            currencyRate: CURRENCY_RATES.EUR_TO_AUD
        };
        
        // Cache the result
        dataStore.smsCache[cacheKey] = {
            data: result,
            timestamp: Date.now()
        };
        
        res.json(result);
        
    } catch (error) {
        console.error('SMS usage error:', error);
        res.status(500).json({
            success: false,
            error: error.message,
            data: processRecords([]).aggregated,
            perAccount: {}
        });
    }
});

// Get SMS for specific date
app.get('/api/vonage/usage/sms/:date', authenticateToken, async (req, res) => {
    try {
        const { date } = req.params;
        
        // Validate date format
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
        
        if (!response.data?.request_id) {
            return res.json({
                success: false,
                message: `No data for ${date}`,
                data: processRecords([]).aggregated,
                date: date
            });
        }
        
        // Poll for results
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
                    const reportData = processRecords(records);
                    
                    return res.json({
                        success: true,
                        data: reportData.aggregated,
                        perAccount: reportData.perAccountDetail,
                        date: date,
                        recordCount: records.length,
                        activeAccounts: Object.keys(reportData.perAccountDetail).length
                    });
                }
            }
        }
        
        res.json({
            success: false,
            message: `No data available for ${date}`,
            data: processRecords([]).aggregated,
            date: date
        });
        
    } catch (error) {
        console.error(`Error fetching data for date ${req.params.date}:`, error);
        res.status(500).json({
            success: false,
            error: error.message,
            data: processRecords([]).aggregated
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
        
        if (!response.data?.request_id) {
            return res.json({
                success: false,
                message: 'Could not create debug report'
            });
        }
        
        // Poll for results
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
                        // Analyze fields
                        const fieldNames = Object.keys(records[0]);
                        const potentialAccountFields = {};
                        
                        // Check fields that might contain account info
                        for (const field of fieldNames) {
                            const fieldLower = field.toLowerCase();
                            if (fieldLower.includes('account') || 
                                fieldLower.includes('api') || 
                                fieldLower.includes('key') ||
                                fieldLower.includes('client') ||
                                fieldLower.includes('ref') ||
                                fieldLower.includes('sender') ||
                                fieldLower.includes('from')) {
                                
                                // Get unique values for this field
                                const uniqueValues = new Set();
                                for (let j = 0; j < Math.min(100, records.length); j++) {
                                    if (records[j][field]) {
                                        uniqueValues.add(records[j][field]);
                                    }
                                }
                                
                                if (uniqueValues.size > 0) {
                                    potentialAccountFields[field] = Array.from(uniqueValues).slice(0, 5);
                                }
                            }
                        }
                        
                        return res.json({
                            success: true,
                            totalRecords: records.length,
                            allFields: fieldNames,
                            potentialAccountFields: potentialAccountFields,
                            sampleRecord: records[0],
                            firstThreeRecords: records.slice(0, 3)
                        });
                    }
                }
            }
        }
        
        res.json({
            success: false,
            message: 'Could not get CSV fields'
        });
        
    } catch (error) {
        console.error('Debug error:', error);
        res.status(500).json({
            success: false,
            error: error.message
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
                balance: a.balance,
                created_at: a.created_at
            }))
        });
        
    } catch (error) {
        console.error('Error listing sub-accounts:', error.message);
        res.json({
            success: false,
            error: error.message,
            count: 0,
            accounts: []
        });
    }
});

// Test endpoint for specific date/time range
app.get('/api/test/exact-vonage', authenticateToken, async (req, res) => {
    try {
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        const headers = {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json'
        };
        
        // Test with the exact parameters that worked before
        const body = {
            "account_id": "f3fa74ea",
            "product": "SMS",
            "include_subaccounts": "true",
            "direction": "outbound",
            "date_start": "2025-09-24T05:00:00+0000",
            "date_end": "2025-09-24T07:00:00+0000"
        };
        
        console.log('\n=== EXACT VONAGE TEST REQUEST ===');
        console.log('Body:', JSON.stringify(body, null, 2));
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000
        });
        
        if (!response.data?.request_id) {
            return res.json({
                success: false,
                message: 'No request_id returned',
                response: response.data
            });
        }
        
        console.log('Got request_id:', response.data.request_id);
        
        // Poll for results with longer timeout
        for (let i = 1; i <= 30; i++) {
            await new Promise(resolve => setTimeout(resolve, 5000));
            
            const statusUrl = `https://api.nexmo.com/v2/reports/${response.data.request_id}`;
            const statusResponse = await axios.get(statusUrl, { headers });
            
            console.log(`Attempt ${i}: Status = ${statusResponse.data?.request_status}`);
            
            if (statusResponse.data?.request_status === 'SUCCESS') {
                const downloadUrl = statusResponse.data?._links?.download_report?.href;
                
                if (downloadUrl) {
                    const dlResponse = await axios.get(downloadUrl, { 
                        headers,
                        responseType: 'arraybuffer'
                    });
                    
                    const records = await extractAndParseCSV(dlResponse.data, true);
                    const reportData = processRecords(records);
                    
                    return res.json({
                        success: true,
                        recordCount: records.length,
                        data: reportData.aggregated,
                        perAccount: reportData.perAccountDetail,
                        type: 'parsed-csv-from-zip'
                    });
                }
            }
        }
        
        res.json({
            success: false,
            message: 'Report processing timeout',
            requestId: response.data.request_id
        });
        
    } catch (error) {
        console.error('Test endpoint error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Redirect old endpoints to new ones
app.get('/api/vonage/usage/sms', authenticateToken, (req, res) => {
    res.redirect('/api/vonage/usage/sms/today-safe');
});

app.get('/api/vonage/usage/current', authenticateToken, (req, res) => {
    res.redirect('/api/vonage/usage/sms/today-safe');
});

// Error handling
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
    console.error('Server error:', err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`Chatti Platform Server Starting...`);
    console.log(`========================================`);
    console.log(`Port: ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`URL: http://localhost:${PORT}`);
    
    console.log(`\n=== CONFIGURATION STATUS ===`);
    console.log(`✅ VONAGE_API_KEY: ${config.vonage.apiKey}`);
    console.log(`✅ VONAGE_API_SECRET: ${config.vonage.apiSecret ? 'Set' : 'NOT SET - Required!'}`);
    console.log(`✅ VONAGE_ACCOUNT_ID: ${config.vonage.accountId}`);
    console.log(`✅ JWT_SECRET: ${JWT_SECRET === 'your-secret-key-change-this-in-production' ? 'Using default (change in production!)' : 'Set'}`);
    
    console.log(`\n=== FEATURES ===`);
    console.log('✅ ZIP file extraction');
    console.log('✅ CSV parsing');
    console.log('✅ EUR to AUD currency conversion');
    console.log('✅ 30-minute caching');
    console.log('✅ Sub-account detection');
    console.log('✅ Debug endpoints');
    
    console.log(`\n=== ENDPOINTS ===`);
    console.log('POST /api/login - Authentication');
    console.log('GET  /api/vonage/test - Test Vonage connection');
    console.log('GET  /api/vonage/usage/sms/today-safe - Today\'s SMS data');
    console.log('GET  /api/vonage/usage/sms/:date - SMS data for specific date');
    console.log('GET  /api/vonage/subaccounts/list - List all sub-accounts');
    console.log('GET  /api/debug/csv-fields - Debug CSV field names');
    console.log('GET  /api/test/exact-vonage - Test with known working parameters');
    
    console.log('\n========================================\n');
});