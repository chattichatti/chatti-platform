// server.js - Complete Chatti Platform Backend
// Queries multiple Vonage sub-accounts for SMS data

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const AdmZip = require('adm-zip');

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Configuration from environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';
const VONAGE_API_KEY = process.env.VONAGE_API_KEY || '4c42609f';
const VONAGE_API_SECRET = process.env.VONAGE_API_SECRET || '';
const CURRENCY_RATES = { EUR_TO_AUD: 1.64 };

// Log startup
console.log('Starting Chatti Platform server...');
console.log('VONAGE_API_KEY:', VONAGE_API_KEY);
console.log('VONAGE_API_SECRET is', VONAGE_API_SECRET ? 'SET' : 'NOT SET - REQUIRED!');

// Simple user store for authentication
const users = [{
    id: 1,
    email: 'admin@chatti.com',
    passwordHash: '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9',
    role: 'admin',
    name: 'Admin User'
}];

// Cache store
let dataStore = { smsCache: {} };

// =================== HELPER FUNCTIONS ===================

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

async function extractAndParseCSV(data, isBuffer = false) {
    let csvData = null;
    
    if (isBuffer) {
        const buffer = Buffer.from(data);
        
        // Check if it's a ZIP file
        if (buffer[0] === 0x50 && buffer[1] === 0x4B) {
            console.log('Extracting CSV from ZIP...');
            const zip = new AdmZip(buffer);
            const zipEntries = zip.getEntries();
            
            for (const entry of zipEntries) {
                if (entry.entryName.endsWith('.csv')) {
                    csvData = zip.readAsText(entry);
                    break;
                }
            }
        } else {
            csvData = buffer.toString('utf8');
        }
    } else if (typeof data === 'string') {
        csvData = data;
    }
    
    if (!csvData) return [];
    
    // Parse CSV
    const lines = csvData.split('\n').filter(line => line.trim());
    const headers = parseCSVLine(lines[0]);
    const records = [];
    
    for (let i = 1; i < lines.length; i++) {
        const values = parseCSVLine(lines[i]);
        const record = {};
        headers.forEach((header, index) => {
            record[header] = values[index] || '';
        });
        records.push(record);
    }
    
    console.log(`Parsed ${records.length} records`);
    return records;
}

function processRecords(records) {
    const result = {
        total: 0,
        outbound: 0,
        byCountry: {},
        totalCost: 0,
        totalCostAUD: 0
    };
    
    if (!Array.isArray(records)) return { aggregated: result };
    
    for (const record of records) {
        result.total++;
        
        if (record.direction === 'outbound' || record.direction === 'OUTBOUND') {
            result.outbound++;
        }
        
        const costEUR = parseFloat(record.total_price || record.price || 0);
        result.totalCost += costEUR;
        result.totalCostAUD += costEUR * CURRENCY_RATES.EUR_TO_AUD;
        
        const country = record.country_name || record.country || 'Unknown';
        if (!result.byCountry[country]) {
            result.byCountry[country] = { count: 0, cost: 0, costAUD: 0 };
        }
        result.byCountry[country].count++;
        result.byCountry[country].cost += costEUR;
        result.byCountry[country].costAUD += costEUR * CURRENCY_RATES.EUR_TO_AUD;
    }
    
    return { aggregated: result };
}

// =================== AUTH MIDDLEWARE ===================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ success: false, message: 'No token' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Invalid token' });
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
    res.json({ status: 'OK', message: 'Server is running' });
});

// Login
app.post('/api/login', (req, res) => {
    const { email, passHash } = req.body;
    const user = users.find(u => u.email === email && u.passwordHash === passHash);
    
    if (!user) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token, user });
});

// Test Vonage connection
app.get('/api/vonage/test', authenticateToken, async (req, res) => {
    try {
        if (!VONAGE_API_SECRET) {
            return res.json({ 
                success: false, 
                error: 'VONAGE_API_SECRET not set in environment' 
            });
        }
        
        const auth = Buffer.from(`${VONAGE_API_KEY}:${VONAGE_API_SECRET}`).toString('base64');
        const response = await axios.get('https://rest.nexmo.com/account/get-balance', {
            headers: { 'Authorization': `Basic ${auth}` }
        });
        
        res.json({ 
            success: true, 
            balance: response.data.value,
            currency: response.data.currency 
        });
    } catch (error) {
        res.json({ 
            success: false, 
            error: error.message 
        });
    }
});

// Get list of all sub-accounts
app.get('/api/vonage/subaccounts/list', authenticateToken, async (req, res) => {
    try {
        if (!VONAGE_API_SECRET) {
            return res.json({ success: false, error: 'API Secret not configured', accounts: [] });
        }
        
        const auth = Buffer.from(`${VONAGE_API_KEY}:${VONAGE_API_SECRET}`).toString('base64');
        const url = `https://api.nexmo.com/accounts/${VONAGE_API_KEY}/subaccounts`;
        
        console.log('Fetching sub-accounts list...');
        
        const response = await axios.get(url, {
            headers: { 'Authorization': `Basic ${auth}` },
            timeout: 10000
        });
        
        let accounts = [];
        if (response.data?._embedded?.subaccounts) {
            accounts = response.data._embedded.subaccounts;
        }
        
        console.log(`Found ${accounts.length} sub-accounts`);
        
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
        res.json({ success: false, error: error.message, accounts: [] });
    }
});

// Query single sub-account (for testing)
app.get('/api/vonage/usage/sms/single-account', authenticateToken, async (req, res) => {
    try {
        if (!VONAGE_API_SECRET) {
            return res.json({
                success: false,
                error: 'VONAGE_API_SECRET not configured',
                data: { total: 0, totalCost: 0, totalCostAUD: 0, byCountry: {} }
            });
        }
        
        const auth = Buffer.from(`${VONAGE_API_KEY}:${VONAGE_API_SECRET}`).toString('base64');
        const headers = {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json'
        };
        
        const today = new Date().toISOString().slice(0, 10);
        const accountId = req.query.account_id || 'f3fa74ea';
        
        const body = {
            "account_id": accountId,
            "product": "SMS",
            "direction": "outbound",
            "date_start": `${today}T00:00:00+0000`,
            "date_end": `${today}T23:59:59+0000`
        };
        
        console.log(`Querying single account ${accountId}...`);
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000
        });
        
        if (!response.data?.request_id) {
            return res.json({
                success: false,
                message: 'No data',
                data: { total: 0, totalCost: 0, totalCostAUD: 0, byCountry: {} }
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
                        responseType: 'arraybuffer'
                    });
                    
                    const records = await extractAndParseCSV(dlResponse.data, true);
                    const reportData = processRecords(records);
                    
                    return res.json({
                        success: true,
                        accountId: accountId,
                        data: reportData.aggregated,
                        recordCount: records.length,
                        currencyRate: CURRENCY_RATES.EUR_TO_AUD
                    });
                }
            }
        }
        
        res.json({
            success: false,
            message: 'Timeout',
            data: { total: 0, totalCost: 0, totalCostAUD: 0, byCountry: {} }
        });
        
    } catch (error) {
        console.error('Error:', error.message);
        res.json({
            success: false,
            error: error.message,
            data: { total: 0, totalCost: 0, totalCostAUD: 0, byCountry: {} }
        });
    }
});

// Query multiple sub-accounts
app.get('/api/vonage/usage/sms/all-accounts', authenticateToken, async (req, res) => {
    try {
        if (!VONAGE_API_SECRET) {
            return res.json({ success: false, error: 'API Secret not configured' });
        }
        
        const auth = Buffer.from(`${VONAGE_API_KEY}:${VONAGE_API_SECRET}`).toString('base64');
        const headers = {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json'
        };
        
        const today = new Date().toISOString().slice(0, 10);
        
        // Check cache (1 hour)
        const cacheKey = `all_accounts_${today}`;
        if (dataStore.smsCache[cacheKey] && 
            (Date.now() - dataStore.smsCache[cacheKey].timestamp) < 60 * 60 * 1000) {
            console.log('Returning cached data');
            return res.json(dataStore.smsCache[cacheKey].data);
        }
        
        // Get list of sub-accounts
        const accountsUrl = `https://api.nexmo.com/accounts/${VONAGE_API_KEY}/subaccounts`;
        console.log('Getting sub-accounts list...');
        
        const accountsResponse = await axios.get(accountsUrl, {
            headers: { 'Authorization': `Basic ${auth}` },
            timeout: 10000
        });
        
        let subAccounts = [];
        if (accountsResponse.data?._embedded?.subaccounts) {
            subAccounts = accountsResponse.data._embedded.subaccounts;
        }
        
        console.log(`Found ${subAccounts.length} sub-accounts`);
        
        // Limit for testing - REMOVE THIS to query all accounts
        const limit = parseInt(req.query.limit || '10');
        const accountsToQuery = subAccounts.slice(0, limit);
        console.log(`Querying ${accountsToQuery.length} accounts (limit: ${limit})`);
        
        // Combined results
        const allAccountsData = {
            total: 0,
            outbound: 0,
            byCountry: {},
            totalCost: 0,
            totalCostAUD: 0
        };
        
        const perAccountDetail = {};
        let successfulQueries = 0;
        let failedQueries = [];
        
        // Query each sub-account
        for (const account of accountsToQuery) {
            try {
                console.log(`Querying ${account.api_key}...`);
                
                const body = {
                    "account_id": account.api_key,
                    "product": "SMS",
                    "direction": "outbound",
                    "date_start": `${today}T00:00:00+0000`,
                    "date_end": `${today}T23:59:59+0000`
                };
                
                const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
                    headers,
                    timeout: 30000
                });
                
                if (!response.data?.request_id) {
                    console.log(`No data for ${account.api_key}`);
                    continue;
                }
                
                // Poll for results
                let accountData = null;
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
                            accountData = processRecords(records);
                            console.log(`${account.api_key}: ${records.length} SMS`);
                            break;
                        }
                    }
                }
                
                if (accountData && accountData.aggregated.total > 0) {
                    successfulQueries++;
                    
                    // Add to totals
                    allAccountsData.total += accountData.aggregated.total;
                    allAccountsData.outbound += accountData.aggregated.outbound;
                    allAccountsData.totalCost += accountData.aggregated.totalCost;
                    allAccountsData.totalCostAUD += accountData.aggregated.totalCostAUD;
                    
                    // Per-account detail
                    perAccountDetail[account.api_key] = {
                        accountId: account.api_key,
                        name: account.name || 'Unnamed',
                        count: accountData.aggregated.total,
                        cost: accountData.aggregated.totalCost,
                        costAUD: accountData.aggregated.totalCostAUD,
                        countries: Object.keys(accountData.aggregated.byCountry)
                    };
                    
                    // Merge country data
                    for (const [country, data] of Object.entries(accountData.aggregated.byCountry)) {
                        if (!allAccountsData.byCountry[country]) {
                            allAccountsData.byCountry[country] = {
                                count: 0,
                                cost: 0,
                                costAUD: 0
                            };
                        }
                        allAccountsData.byCountry[country].count += data.count;
                        allAccountsData.byCountry[country].cost += data.cost;
                        allAccountsData.byCountry[country].costAUD += data.costAUD;
                    }
                }
                
                // Small delay to avoid rate limiting
                await new Promise(resolve => setTimeout(resolve, 500));
                
            } catch (error) {
                console.error(`Failed ${account.api_key}:`, error.message);
                failedQueries.push({ accountId: account.api_key, error: error.message });
            }
        }
        
        console.log(`Complete: ${successfulQueries} successful, ${failedQueries.length} failed`);
        
        const result = {
            success: true,
            data: allAccountsData,
            perAccount: perAccountDetail,
            recordCount: allAccountsData.total,
            activeAccounts: successfulQueries,
            totalAccountsQueried: accountsToQuery.length,
            totalAccountsAvailable: subAccounts.length,
            failedAccounts: failedQueries,
            date: today,
            currencyRate: CURRENCY_RATES.EUR_TO_AUD
        };
        
        // Cache result
        dataStore.smsCache[cacheKey] = {
            data: result,
            timestamp: Date.now()
        };
        
        res.json(result);
        
    } catch (error) {
        console.error('Error:', error.message);
        res.json({ success: false, error: error.message });
    }
});

// Error handler
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`Chatti Platform Server`);
    console.log(`Port: ${PORT}`);
    console.log(`VONAGE_API_KEY: ${VONAGE_API_KEY}`);
    console.log(`VONAGE_API_SECRET: ${VONAGE_API_SECRET ? 'SET' : 'NOT SET - REQUIRED!'}`);
    console.log(`========================================\n`);
});