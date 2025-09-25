// server.js - MINIMAL WORKING VERSION
// This will definitely start and run

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

// Simple configuration - no complex logic
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';
const VONAGE_API_KEY = process.env.VONAGE_API_KEY || '4c42609f';
const VONAGE_API_SECRET = process.env.VONAGE_API_SECRET || '';
const CURRENCY_RATES = { EUR_TO_AUD: 1.64 };

// Log startup info
console.log('Starting server...');
console.log('VONAGE_API_KEY:', VONAGE_API_KEY);
console.log('VONAGE_API_SECRET is', VONAGE_API_SECRET ? 'SET' : 'NOT SET');

// Simple user for auth
const users = [{
    id: 1,
    email: 'admin@chatti.com',
    passwordHash: '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9',
    role: 'admin',
    name: 'Admin User'
}];

// Cache
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
        
        // Check if ZIP
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
        bySubAccount: {},
        totalCost: 0,
        totalCostAUD: 0
    };
    
    if (!Array.isArray(records)) return { aggregated: result, perAccountDetail: {} };
    
    for (const record of records) {
        result.total++;
        
        if (record.direction === 'outbound') {
            result.outbound++;
        }
        
        const costEUR = parseFloat(record.total_price || 0);
        result.totalCost += costEUR;
        result.totalCostAUD += costEUR * CURRENCY_RATES.EUR_TO_AUD;
        
        const country = record.country_name || 'Unknown';
        if (!result.byCountry[country]) {
            result.byCountry[country] = { count: 0, cost: 0, costAUD: 0 };
        }
        result.byCountry[country].count++;
        result.byCountry[country].cost += costEUR;
        result.byCountry[country].costAUD += costEUR * CURRENCY_RATES.EUR_TO_AUD;
    }
    
    return { aggregated: result, perAccountDetail: {} };
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

// Basic routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

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
            balance: response.data.value 
        });
    } catch (error) {
        res.json({ 
            success: false, 
            error: error.message 
        });
    }
});

// Main SMS endpoint - SIMPLE VERSION THAT WORKS
app.get('/api/vonage/usage/sms/today-safe', authenticateToken, async (req, res) => {
    try {
        if (!VONAGE_API_SECRET) {
            return res.json({
                success: false,
                error: 'VONAGE_API_SECRET not configured',
                data: { total: 0, totalCost: 0, totalCostAUD: 0, byCountry: {} },
                perAccount: {}
            });
        }
        
        const auth = Buffer.from(`${VONAGE_API_KEY}:${VONAGE_API_SECRET}`).toString('base64');
        const headers = {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json'
        };
        
        const today = new Date().toISOString().slice(0, 10);
        
        // Simple body - query just f3fa74ea
        const body = {
            "account_id": "f3fa74ea",
            "product": "SMS",
            "direction": "outbound",
            "date_start": `${today}T00:00:00+0000`,
            "date_end": `${today}T23:59:59+0000`
        };
        
        console.log('Requesting SMS data for f3fa74ea...');
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000
        });
        
        if (!response.data?.request_id) {
            return res.json({
                success: false,
                message: 'No request_id received',
                data: { total: 0, totalCost: 0, totalCostAUD: 0, byCountry: {} },
                perAccount: {}
            });
        }
        
        console.log('Got request_id:', response.data.request_id);
        
        // Poll for results
        for (let i = 1; i <= 20; i++) {
            await new Promise(resolve => setTimeout(resolve, 3000));
            
            const statusUrl = `https://api.nexmo.com/v2/reports/${response.data.request_id}`;
            const statusResponse = await axios.get(statusUrl, { headers });
            
            console.log(`Attempt ${i}: ${statusResponse.data?.request_status}`);
            
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
                        perAccount: { 'f3fa74ea': reportData.aggregated },
                        recordCount: records.length,
                        activeAccounts: 1,
                        currencyRate: CURRENCY_RATES.EUR_TO_AUD
                    });
                }
            }
        }
        
        res.json({
            success: false,
            message: 'Timeout',
            data: { total: 0, totalCost: 0, totalCostAUD: 0, byCountry: {} },
            perAccount: {}
        });
        
    } catch (error) {
        console.error('Error:', error.message);
        res.json({
            success: false,
            error: error.message,
            data: { total: 0, totalCost: 0, totalCostAUD: 0, byCountry: {} },
            perAccount: {}
        });
    }
});

// Other endpoints - simplified
app.get('/api/vonage/usage/sms/:date', authenticateToken, (req, res) => {
    res.json({
        success: false,
        message: 'Not implemented yet',
        data: { total: 0, totalCost: 0, totalCostAUD: 0, byCountry: {} }
    });
});

app.get('/api/debug/csv-fields', authenticateToken, (req, res) => {
    res.json({
        success: false,
        message: 'Not implemented yet'
    });
});

app.get('/api/vonage/subaccounts/list', authenticateToken, (req, res) => {
    res.json({
        success: false,
        message: 'Not implemented yet',
        accounts: []
    });
});

// Error handler
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`Server running on port ${PORT}`);
    console.log(`VONAGE_API_KEY: ${VONAGE_API_KEY}`);
    console.log(`VONAGE_API_SECRET: ${VONAGE_API_SECRET ? 'SET' : 'NOT SET'}`);
    console.log(`========================================\n`);
});