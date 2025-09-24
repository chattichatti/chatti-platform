// server.js - Complete Backend Server for Chatti Platform with Vonage Reseller Integration
// Version: Individual sub-account querying (one at a time)

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

// =============== INDIVIDUAL SUB-ACCOUNT QUERYING ===============

async function fetchSubAccountData(headers, subAccountApiKey, dateStart, dateEnd) {
    try {
        const body = {
            account_id: subAccountApiKey,  // Query specific sub-account
            product: "SMS",
            date_start: `${dateStart}T00:00:00Z`,
            date_end: `${dateEnd}T23:59:59Z`,
            direction: "outbound"
        };
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 10000  // 10 second timeout per sub-account
        });
        
        return response.data?.records || [];
    } catch (error) {
        // Silently fail for individual sub-accounts
        return [];
    }
}

async function fetchAllSubAccountsData(headers, dateStart, dateEnd) {
    console.log('\n=== FETCHING DATA FROM INDIVIDUAL SUB-ACCOUNTS ===');
    
    // Get list of sub-accounts
    const subAccounts = await fetchSubAccounts();
    
    if (subAccounts.length === 0) {
        console.log('No sub-accounts found');
        return [];
    }
    
    console.log(`Found ${subAccounts.length} sub-accounts to query`);
    
    let allRecords = [];
    let successCount = 0;
    let failCount = 0;
    const batchSize = 10; // Process 10 accounts at a time to avoid overwhelming the API
    
    // Process in batches
    for (let i = 0; i < subAccounts.length; i += batchSize) {
        const batch = subAccounts.slice(i, Math.min(i + batchSize, subAccounts.length));
        console.log(`Processing batch ${Math.floor(i/batchSize) + 1} (accounts ${i + 1}-${Math.min(i + batchSize, subAccounts.length)})`);
        
        // Process batch in parallel
        const batchPromises = batch.map(async (subAccount) => {
            try {
                const records = await fetchSubAccountData(headers, subAccount.api_key, dateStart, dateEnd);
                if (records.length > 0) {
                    successCount++;
                    console.log(`✓ ${subAccount.api_key}: ${records.length} records`);
                    return records;
                } else {
                    console.log(`○ ${subAccount.api_key}: No data`);
                    return [];
                }
            } catch (error) {
                failCount++;
                console.log(`✗ ${subAccount.api_key}: Failed`);
                return [];
            }
        });
        
        const batchResults = await Promise.all(batchPromises);
        batchResults.forEach(records => {
            allRecords = allRecords.concat(records);
        });
        
        // Small delay between batches to avoid rate limiting
        if (i + batchSize < subAccounts.length) {
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
    
    console.log(`\n=== SUMMARY ===`);
    console.log(`Successful queries: ${successCount}/${subAccounts.length}`);
    console.log(`Failed queries: ${failCount}/${subAccounts.length}`);
    console.log(`Total records collected: ${allRecords.length}`);
    
    return allRecords;
}

// Master account data fetch
async function fetchMasterAccountData(headers, dateStart, dateEnd) {
    try {
        console.log('\n=== FETCHING MASTER ACCOUNT DATA ===');
        
        const body = {
            account_id: config.vonage.accountId,
            product: "SMS",
            date_start: `${dateStart}T00:00:00Z`,
            date_end: `${dateEnd}T23:59:59Z`,
            direction: "outbound"
        };
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000
        });
        
        const records = response.data?.records || [];
        console.log(`Master account records: ${records.length}`);
        return records;
        
    } catch (error) {
        console.error('Master account query failed:', error.response?.status);
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

// SMS usage endpoint - QUERIES EACH SUB-ACCOUNT INDIVIDUALLY
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
        
        // Prepare headers - use JWT if available, otherwise Basic auth
        let headers;
        const jwtToken = generateVonageJWT();
        
        if (jwtToken) {
            console.log('Using JWT authentication');
            headers = {
                'Authorization': `Bearer ${jwtToken}`,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            };
        } else {
            console.log('Using Basic authentication');
            headers = {
                'Authorization': `Basic ${Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64')}`,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            };
        }
        
        // Fetch data from master account and all sub-accounts individually
        let allRecords = [];
        
        // Get master account data
        const masterRecords = await fetchMasterAccountData(headers, dateStart, dateEnd);
        allRecords = allRecords.concat(masterRecords);
        
        // Get all sub-accounts data (one by one)
        const subAccountRecords = await fetchAllSubAccountsData(headers, dateStart, dateEnd);
        allRecords = allRecords.concat(subAccountRecords);
        
        console.log(`\nTotal records from all accounts: ${allRecords.length}`);
        
        // Process and return the records
        const aggregatedData = processRecords(allRecords);
        
        const result = {
            success: true,
            data: aggregatedData,
            month: month,
            dateRange: `${dateStart} to ${dateEnd}`,
            recordCount: aggregatedData.total,
            method: 'individual-subaccounts',
            accountsQueried: subAccountsCache.data.length + 1  // sub-accounts + master
        };
        
        // Cache the result if we got data
        if (aggregatedData.total > 0) {
            dataStore.smsCache[cacheKey] = {
                data: result,
                timestamp: Date.now()
            };
        }
        
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
        
        let headers;
        const jwtToken = generateVonageJWT();
        
        if (jwtToken) {
            headers = {
                'Authorization': `Bearer ${jwtToken}`,
                'Content-Type': 'application/json'
            };
        } else {
            headers = {
                'Authorization': `Basic ${Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64')}`,
                'Content-Type': 'application/json'
            };
        }
        
        // Get data from all accounts
        let allRecords = [];
        const masterRecords = await fetchMasterAccountData(headers, dateStart, dateEnd);
        allRecords = allRecords.concat(masterRecords);
        
        const subAccountRecords = await fetchAllSubAccountsData(headers, dateStart, dateEnd);
        allRecords = allRecords.concat(subAccountRecords);
        
        const data = processRecords(allRecords);
        
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
        console.log('ℹ️  VONAGE_APPLICATION_ID: Not set (using Basic auth)');
    } else {
        console.log('✅ VONAGE_APPLICATION_ID: Configured');
    }
    
    console.log('\n========================================\n');
});