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

// =================== MAIN TEST ENDPOINTS ===================

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
        };
        
        console.log('\n=== EXACT VONAGE SUPPORT REQUEST ===');
        console.log('Using master key:', config.vonage.apiKey);
        console.log('Using master secret:', config.vonage.apiSecret ? 'Set' : 'Not Set');
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
            
            // Poll for results - FIX THE STATUS CHECK
            for (let i = 1; i <= 30; i++) {
                await new Promise(resolve => setTimeout(resolve, 5000));
                
                const statusUrl = `https://api.nexmo.com/v2/reports/${response.data.request_id}`;
                const statusResponse = await axios.get(statusUrl, { 
                    headers,
                    validateStatus: () => true 
                });
                
                // Log the ENTIRE response to see what we're getting
                console.log(`Poll ${i}/30 - Full response:`, JSON.stringify(statusResponse.data));
                
                // Check various possible status fields
                const status = statusResponse.data?.status || 
                              statusResponse.data?.request_status ||  // THIS IS THE RIGHT FIELD!
                              statusResponse.data?.report_status || 
                              statusResponse.data?.state ||
                              'unknown';
                              
                console.log(`Poll ${i}/30: status=${status}`);
                
                // Check if completed - SUCCESS means done!
                if (status === 'SUCCESS' || status === 'completed' || status === 'COMPLETED' || 
                    status === 'complete' || status === 'COMPLETE' ||
                    statusResponse.data?._links?.download_report?.href) {  // CORRECT DOWNLOAD URL PATH
                    
                    // The download URL is in _links.download_report.href
                    const downloadUrl = statusResponse.data?._links?.download_report?.href || 
                                       statusResponse.data?.download_url;
                    
                    if (downloadUrl) {
                        console.log('Downloading from:', downloadUrl);
                        const dlResponse = await axios.get(downloadUrl, { headers, timeout: 60000 });
                        
                        // The response might be JSON or CSV
                        if (dlResponse.data?.records) {
                            const data = processRecords(dlResponse.data.records);
                            return res.json({
                                success: true,
                                recordCount: dlResponse.data.records.length,
                                data: data,
                                type: 'async-downloaded-json'
                            });
                        }
                        
                        // If it's CSV format (string), parse it
                        if (typeof dlResponse.data === 'string' && dlResponse.data.includes(',')) {
                            console.log('Got CSV data, parsing...');
                            
                            // Simple CSV parser for the SMS data
                            const lines = dlResponse.data.split('\n');
                            const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, ''));
                            const records = [];
                            
                            for (let i = 1; i < lines.length; i++) {
                                if (lines[i].trim()) {
                                    const values = lines[i].split(',').map(v => v.trim().replace(/"/g, ''));
                                    const record = {};
                                    headers.forEach((header, index) => {
                                        record[header] = values[index] || '';
                                    });
                                    records.push(record);
                                }
                            }
                            
                            console.log(`Parsed ${records.length} records from CSV`);
                            const data = processRecords(records);
                            
                            return res.json({
                                success: true,
                                recordCount: records.length,
                                data: data,
                                type: 'csv-parsed'
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
                    
                    // Report says complete but no data found
                    return res.json({
                        success: false,
                        message: 'Report completed but no records found',
                        fullResponse: statusResponse.data
                    });
                }
                
                // Check if failed
                if (status === 'failed' || status === 'FAILED' || status === 'error') {
                    return res.json({
                        success: false,
                        message: 'Report generation failed',
                        status: status,
                        fullResponse: statusResponse.data
                    });
                }
            }
            
            return res.json({
                success: false,
                message: 'Report still processing after 30 attempts',
                requestId: response.data.request_id
            });
        }
        
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

// Quick check - just see what the API returns without complex polling
app.get('/api/test/quick-check', authenticateToken, async (req, res) => {
    try {
        const auth = Buffer.from(`${config.vonage.apiKey}:${config.vonage.apiSecret}`).toString('base64');
        const headers = {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json'
        };
        
        // Test with just 1 hour of data
        const body = {
            "account_id": "f3fa74ea",
            "product": "SMS",
            "include_subaccounts": "true",
            "direction": "outbound",
            "date_start": "2025-09-24T05:00:00+0000",
            "date_end": "2025-09-24T06:00:00+0000"  // Just 1 hour
        };
        
        console.log('Quick check request...');
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 10000
        });
        
        // If we got a request_id, try polling just ONCE to see the structure
        if (response.data?.request_id) {
            await new Promise(resolve => setTimeout(resolve, 5000));
            
            const statusResponse = await axios.get(
                `https://api.nexmo.com/v2/reports/${response.data.request_id}`,
                { headers, validateStatus: () => true }
            );
            
            return res.json({
                step1: 'Got request_id',
                requestId: response.data.request_id,
                step2: 'Polled once after 5 seconds',
                pollResponse: statusResponse.data,
                pollStatus: statusResponse.status
            });
        }
        
        // If synchronous
        return res.json({
            type: 'synchronous',
            hasRecords: !!response.data?.records,
            recordCount: response.data?.records?.length || 0
        });
        
    } catch (error) {
        res.json({ error: error.message });
    }
});

// Placeholder endpoints for UI
app.get('/api/vonage/usage/sms/today-safe', authenticateToken, (req, res) => {
    res.json({
        success: false,
        message: 'Use /api/test/exact-vonage for testing',
        data: processRecords([])
    });
});

app.get('/api/vonage/subaccounts/list', authenticateToken, (req, res) => {
    res.json({
        success: true,
        count: 267,
        accounts: []
    });
});

app.get('/api/test/single-account', authenticateToken, (req, res) => {
    res.redirect('/api/test/exact-vonage');
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
    
    console.log('\n========================================\n');
});