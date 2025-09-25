// CRITICAL SAFETY MEASURES FOR VONAGE API USAGE
// This version includes multiple safeguards to prevent excessive API calls

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const AdmZip = require('adm-zip');

dotenv.config();
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';
const VONAGE_API_KEY = process.env.VONAGE_API_KEY || '4c42609f';
const VONAGE_API_SECRET = process.env.VONAGE_API_SECRET || '';
const CURRENCY_RATES = { EUR_TO_AUD: 1.64 };

// CRITICAL: Add rate limiting and request tracking
const requestTracker = {
    lastFullQuery: null,
    requestCount: 0,
    dailyRequestCount: 0,
    lastResetDate: new Date().toDateString()
};

// SAFETY LIMITS
const SAFETY_CONFIG = {
    MAX_ACCOUNTS_PER_QUERY: 10,  // Never query more than 10 at once
    MIN_HOURS_BETWEEN_FULL_QUERIES: 24,  // Only allow full query once per day
    MAX_DAILY_API_CALLS: 1000,  // Hard limit on daily API calls
    MAX_POLLING_ATTEMPTS: 3,  // Reduce polling attempts
    POLLING_DELAY_MS: 5000,  // Increase delay between polls
    CACHE_DURATION_HOURS: 24  // Cache for 24 hours, not 1
};

// Simple auth store
const users = [{
    id: 1,
    email: 'admin@chatti.com',
    passwordHash: '395aa084e764c0e586c561ab571f7a346df3dbd0257c1d586e4152b93009950e',
    role: 'admin',
    name: 'Admin User'
}];

// Enhanced cache with longer duration
let dataCache = {
    sms: {},
    subaccountsList: null,
    subaccountsListTimestamp: null
};

// Reset daily counter
function resetDailyCounterIfNeeded() {
    const today = new Date().toDateString();
    if (requestTracker.lastResetDate !== today) {
        requestTracker.dailyRequestCount = 0;
        requestTracker.lastResetDate = today;
        console.log('Daily request counter reset');
    }
}

// Check if we can make more API calls
function canMakeApiCall(required = 1) {
    resetDailyCounterIfNeeded();
    if (requestTracker.dailyRequestCount + required > SAFETY_CONFIG.MAX_DAILY_API_CALLS) {
        console.error(`SAFETY LIMIT: Would exceed daily limit of ${SAFETY_CONFIG.MAX_DAILY_API_CALLS} API calls`);
        return false;
    }
    return true;
}

// Track API calls
function trackApiCall(count = 1) {
    requestTracker.requestCount += count;
    requestTracker.dailyRequestCount += count;
    console.log(`API calls made: ${requestTracker.dailyRequestCount}/${SAFETY_CONFIG.MAX_DAILY_API_CALLS} today`);
}

// Helper functions
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

// Auth middleware
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

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Server is running',
        safety: {
            dailyRequestsMade: requestTracker.dailyRequestCount,
            dailyLimit: SAFETY_CONFIG.MAX_DAILY_API_CALLS,
            lastFullQuery: requestTracker.lastFullQuery
        }
    });
});

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
            return res.json({ success: false, error: 'VONAGE_API_SECRET not set' });
        }
        
        if (!canMakeApiCall(1)) {
            return res.json({ success: false, error: 'Daily API limit reached' });
        }
        
        const auth = Buffer.from(`${VONAGE_API_KEY}:${VONAGE_API_SECRET}`).toString('base64');
        
        trackApiCall(1);
        const response = await axios.get('https://rest.nexmo.com/account/get-balance', {
            headers: { 'Authorization': `Basic ${auth}` },
            timeout: 10000
        });
        
        res.json({ 
            success: true, 
            balance: response.data.value,
            currency: response.data.currency,
            apiCallsToday: requestTracker.dailyRequestCount
        });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

// SAFE: Query single sub-account only
app.get('/api/vonage/usage/sms/single-account', authenticateToken, async (req, res) => {
    try {
        const accountId = req.query.account_id || 'f3fa74ea';
        const today = new Date().toISOString().slice(0, 10);
        
        // Check cache first
        const cacheKey = `single_${accountId}_${today}`;
        if (dataCache.sms[cacheKey] && 
            (Date.now() - dataCache.sms[cacheKey].timestamp) < SAFETY_CONFIG.CACHE_DURATION_HOURS * 60 * 60 * 1000) {
            console.log('Returning cached data for', accountId);
            return res.json(dataCache.sms[cacheKey].data);
        }
        
        if (!canMakeApiCall(5)) {  // Estimate 5 calls max for single account
            return res.json({ 
                success: false, 
                error: 'Daily API limit reached',
                cached: false,
                apiCallsToday: requestTracker.dailyRequestCount
            });
        }
        
        const auth = Buffer.from(`${VONAGE_API_KEY}:${VONAGE_API_SECRET}`).toString('base64');
        const headers = {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json'
        };
        
        const body = {
            "account_id": accountId,
            "product": "SMS",
            "direction": "outbound",
            "date_start": `${today}T00:00:00+0000`,
            "date_end": `${today}T23:59:59+0000`
        };
        
        console.log(`Querying single account ${accountId}...`);
        
        trackApiCall(1);
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
        
        // SAFE: Limited polling with timeout
        let reportData = null;
        for (let i = 1; i <= SAFETY_CONFIG.MAX_POLLING_ATTEMPTS; i++) {
            await new Promise(resolve => setTimeout(resolve, SAFETY_CONFIG.POLLING_DELAY_MS));
            
            trackApiCall(1);
            const statusUrl = `https://api.nexmo.com/v2/reports/${response.data.request_id}`;
            const statusResponse = await axios.get(statusUrl, { headers, timeout: 10000 });
            
            if (statusResponse.data?.request_status === 'SUCCESS') {
                const downloadUrl = statusResponse.data?._links?.download_report?.href;
                if (downloadUrl) {
                    trackApiCall(1);
                    const dlResponse = await axios.get(downloadUrl, {
                        headers,
                        responseType: 'arraybuffer',
                        timeout: 30000
                    });
                    
                    const records = await extractAndParseCSV(dlResponse.data, true);
                    reportData = processRecords(records);
                    break;
                }
            }
        }
        
        if (!reportData) {
            return res.json({
                success: false,
                message: 'Report timeout',
                data: { total: 0, totalCost: 0, totalCostAUD: 0, byCountry: {} }
            });
        }
        
        const result = {
            success: true,
            accountId: accountId,
            data: reportData.aggregated,
            recordCount: reportData.aggregated.total,
            currencyRate: CURRENCY_RATES.EUR_TO_AUD,
            apiCallsToday: requestTracker.dailyRequestCount
        };
        
        // Cache result
        dataCache.sms[cacheKey] = {
            data: result,
            timestamp: Date.now()
        };
        
        res.json(result);
        
    } catch (error) {
        console.error('Error:', error.message);
        res.json({
            success: false,
            error: error.message,
            data: { total: 0, totalCost: 0, totalCostAUD: 0, byCountry: {} }
        });
    }
});

// DANGER ZONE: Multiple accounts - HEAVILY RESTRICTED
app.get('/api/vonage/usage/sms/all-accounts', authenticateToken, async (req, res) => {
    // SAFETY: Check if enough time has passed
    if (requestTracker.lastFullQuery) {
        const hoursSinceLastQuery = (Date.now() - requestTracker.lastFullQuery) / (1000 * 60 * 60);
        if (hoursSinceLastQuery < SAFETY_CONFIG.MIN_HOURS_BETWEEN_FULL_QUERIES) {
            const hoursRemaining = (SAFETY_CONFIG.MIN_HOURS_BETWEEN_FULL_QUERIES - hoursSinceLastQuery).toFixed(1);
            return res.json({ 
                success: false, 
                error: `Full query only allowed once every ${SAFETY_CONFIG.MIN_HOURS_BETWEEN_FULL_QUERIES} hours. Wait ${hoursRemaining} more hours.`,
                lastQuery: requestTracker.lastFullQuery,
                apiCallsToday: requestTracker.dailyRequestCount
            });
        }
    }
    
    try {
        const auth = Buffer.from(`${VONAGE_API_KEY}:${VONAGE_API_SECRET}`).toString('base64');
        const today = new Date().toISOString().slice(0, 10);
        
        // Check cache
        const cacheKey = `all_accounts_${today}`;
        if (dataCache.sms[cacheKey] && 
            (Date.now() - dataCache.sms[cacheKey].timestamp) < SAFETY_CONFIG.CACHE_DURATION_HOURS * 60 * 60 * 1000) {
            console.log('Returning cached all-accounts data');
            return res.json(dataCache.sms[cacheKey].data);
        }
        
        // SAFETY: Hard limit on number of accounts
        const requestedLimit = parseInt(req.query.limit || '10');
        const limit = Math.min(requestedLimit, SAFETY_CONFIG.MAX_ACCOUNTS_PER_QUERY);
        
        if (requestedLimit > SAFETY_CONFIG.MAX_ACCOUNTS_PER_QUERY) {
            console.warn(`Requested ${requestedLimit} accounts, limiting to ${SAFETY_CONFIG.MAX_ACCOUNTS_PER_QUERY}`);
        }
        
        // Estimate API calls needed
        const estimatedCalls = limit * 5;  // Rough estimate
        if (!canMakeApiCall(estimatedCalls)) {
            return res.json({ 
                success: false, 
                error: `Would exceed daily limit. Estimated ${estimatedCalls} calls needed.`,
                apiCallsToday: requestTracker.dailyRequestCount,
                dailyLimit: SAFETY_CONFIG.MAX_DAILY_API_CALLS
            });
        }
        
        // Get cached sub-accounts list if available
        let subAccounts = [];
        if (dataCache.subaccountsList && 
            (Date.now() - dataCache.subaccountsListTimestamp) < 24 * 60 * 60 * 1000) {
            subAccounts = dataCache.subaccountsList;
            console.log('Using cached subaccounts list');
        } else {
            trackApiCall(1);
            const accountsUrl = `https://api.nexmo.com/accounts/${VONAGE_API_KEY}/subaccounts`;
            const accountsResponse = await axios.get(accountsUrl, {
                headers: { 'Authorization': `Basic ${auth}` },
                timeout: 10000
            });
            
            if (accountsResponse.data?._embedded?.subaccounts) {
                subAccounts = accountsResponse.data._embedded.subaccounts;
                dataCache.subaccountsList = subAccounts;
                dataCache.subaccountsListTimestamp = Date.now();
            }
        }
        
        console.log(`Found ${subAccounts.length} sub-accounts, will query ${limit}`);
        
        // Query limited number of accounts
        const accountsToQuery = subAccounts.slice(0, limit);
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
        
        for (const account of accountsToQuery) {
            try {
                console.log(`Querying ${account.api_key}...`);
                
                // Check individual cache first
                const accountCacheKey = `single_${account.api_key}_${today}`;
                if (dataCache.sms[accountCacheKey] && 
                    (Date.now() - dataCache.sms[accountCacheKey].timestamp) < SAFETY_CONFIG.CACHE_DURATION_HOURS * 60 * 60 * 1000) {
                    console.log(`Using cached data for ${account.api_key}`);
                    const cachedData = dataCache.sms[accountCacheKey].data;
                    if (cachedData.data.total > 0) {
                        successfulQueries++;
                        allAccountsData.total += cachedData.data.total;
                        allAccountsData.outbound += cachedData.data.outbound;
                        allAccountsData.totalCost += cachedData.data.totalCost;
                        allAccountsData.totalCostAUD += cachedData.data.totalCostAUD;
                        
                        perAccountDetail[account.api_key] = {
                            accountId: account.api_key,
                            name: account.name || 'Unnamed',
                            count: cachedData.data.total,
                            cost: cachedData.data.totalCost,
                            costAUD: cachedData.data.totalCostAUD,
                            countries: Object.keys(cachedData.data.byCountry)
                        };
                    }
                    continue;
                }
                
                const headers = {
                    'Authorization': `Basic ${auth}`,
                    'Content-Type': 'application/json'
                };
                
                const body = {
                    "account_id": account.api_key,
                    "product": "SMS",
                    "direction": "outbound",
                    "date_start": `${today}T00:00:00+0000`,
                    "date_end": `${today}T23:59:59+0000`
                };
                
                trackApiCall(1);
                const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
                    headers,
                    timeout: 30000
                });
                
                if (!response.data?.request_id) {
                    console.log(`No data for ${account.api_key}`);
                    continue;
                }
                
                // Limited polling
                let accountData = null;
                for (let i = 1; i <= SAFETY_CONFIG.MAX_POLLING_ATTEMPTS; i++) {
                    await new Promise(resolve => setTimeout(resolve, SAFETY_CONFIG.POLLING_DELAY_MS));
                    
                    trackApiCall(1);
                    const statusUrl = `https://api.nexmo.com/v2/reports/${response.data.request_id}`;
                    const statusResponse = await axios.get(statusUrl, { headers, timeout: 10000 });
                    
                    if (statusResponse.data?.request_status === 'SUCCESS') {
                        const downloadUrl = statusResponse.data?._links?.download_report?.href;
                        if (downloadUrl) {
                            trackApiCall(1);
                            const dlResponse = await axios.get(downloadUrl, {
                                headers,
                                responseType: 'arraybuffer',
                                timeout: 30000
                            });
                            
                            const records = await extractAndParseCSV(dlResponse.data, true);
                            accountData = processRecords(records);
                            console.log(`${account.api_key}: ${records.length} SMS`);
                            
                            // Cache individual account data
                            dataCache.sms[accountCacheKey] = {
                                data: {
                                    success: true,
                                    accountId: account.api_key,
                                    data: accountData.aggregated
                                },
                                timestamp: Date.now()
                            };
                            break;
                        }
                    }
                }
                
                if (accountData && accountData.aggregated.total > 0) {
                    successfulQueries++;
                    allAccountsData.total += accountData.aggregated.total;
                    allAccountsData.outbound += accountData.aggregated.outbound;
                    allAccountsData.totalCost += accountData.aggregated.totalCost;
                    allAccountsData.totalCostAUD += accountData.aggregated.totalCostAUD;
                    
                    perAccountDetail[account.api_key] = {
                        accountId: account.api_key,
                        name: account.name || 'Unnamed',
                        count: accountData.aggregated.total,
                        cost: accountData.aggregated.totalCost,
                        costAUD: accountData.aggregated.totalCostAUD,
                        countries: Object.keys(accountData.aggregated.byCountry)
                    };
                    
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
                
                // SAFETY: Delay between accounts
                await new Promise(resolve => setTimeout(resolve, 1000));
                
            } catch (error) {
                console.error(`Failed ${account.api_key}:`, error.message);
                failedQueries.push({ accountId: account.api_key, error: error.message });
            }
        }
        
        console.log(`Complete: ${successfulQueries} successful, ${failedQueries.length} failed`);
        requestTracker.lastFullQuery = Date.now();
        
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
            currencyRate: CURRENCY_RATES.EUR_TO_AUD,
            apiCallsToday: requestTracker.dailyRequestCount,
            warning: limit < subAccounts.length ? `LIMITED TO ${limit} ACCOUNTS FOR SAFETY` : null
        };
        
        // Cache result
        dataCache.sms[cacheKey] = {
            data: result,
            timestamp: Date.now()
        };
        
        res.json(result);
        
    } catch (error) {
        console.error('Error:', error.message);
        res.json({ success: false, error: error.message });
    }
});

// Get list of sub-accounts (cached)
app.get('/api/vonage/subaccounts/list', authenticateToken, async (req, res) => {
    try {
        // Use cached list if available
        if (dataCache.subaccountsList && 
            (Date.now() - dataCache.subaccountsListTimestamp) < 24 * 60 * 60 * 1000) {
            return res.json({
                success: true,
                count: dataCache.subaccountsList.length,
                accounts: dataCache.subaccountsList.map(a => ({
                    api_key: a.api_key,
                    name: a.name || 'Unnamed',
                    balance: a.balance,
                    created_at: a.created_at
                })),
                cached: true
            });
        }
        
        if (!canMakeApiCall(1)) {
            return res.json({ success: false, error: 'Daily API limit reached', accounts: [] });
        }
        
        const auth = Buffer.from(`${VONAGE_API_KEY}:${VONAGE_API_SECRET}`).toString('base64');
        const url = `https://api.nexmo.com/accounts/${VONAGE_API_KEY}/subaccounts`;
        
        trackApiCall(1);
        const response = await axios.get(url, {
            headers: { 'Authorization': `Basic ${auth}` },
            timeout: 10000
        });
        
        let accounts = [];
        if (response.data?._embedded?.subaccounts) {
            accounts = response.data._embedded.subaccounts;
            dataCache.subaccountsList = accounts;
            dataCache.subaccountsListTimestamp = Date.now();
        }
        
        res.json({
            success: true,
            count: accounts.length,
            accounts: accounts.map(a => ({
                api_key: a.api_key,
                name: a.name || 'Unnamed',
                balance: a.balance,
                created_at: a.created_at
            })),
            cached: false
        });
        
    } catch (error) {
        console.error('Error listing sub-accounts:', error.message);
        res.json({ success: false, error: error.message, accounts: [] });
    }
});

// API usage stats endpoint
app.get('/api/stats', authenticateToken, (req, res) => {
    resetDailyCounterIfNeeded();
    res.json({
        daily: {
            used: requestTracker.dailyRequestCount,
            limit: SAFETY_CONFIG.MAX_DAILY_API_CALLS,
            remaining: SAFETY_CONFIG.MAX_DAILY_API_CALLS - requestTracker.dailyRequestCount
        },
        lastFullQuery: requestTracker.lastFullQuery,
        totalRequestsMade: requestTracker.requestCount,
        safetyLimits: SAFETY_CONFIG
    });
});

app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`SAFE Chatti Platform Server`);
    console.log(`Port: ${PORT}`);
    console.log(`Safety Limits:`);
    console.log(`- Max ${SAFETY_CONFIG.MAX_ACCOUNTS_PER_QUERY} accounts per query`);
    console.log(`- Max ${SAFETY_CONFIG.MAX_DAILY_API_CALLS} API calls per day`);
    console.log(`- ${SAFETY_CONFIG.CACHE_DURATION_HOURS} hour cache`);
    console.log(`- Full query only once per ${SAFETY_CONFIG.MIN_HOURS_BETWEEN_FULL_QUERIES} hours`);
    console.log(`========================================\n`);
});