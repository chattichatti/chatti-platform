// server.js - Chatti Platform backend (secure hash login + Vonage Reports async ZIP flow)

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const jwt = require('jsonwebtoken');        // for your app's session token AND Vonage app JWT (RS256)
const crypto = require('crypto');
const AdmZip = require('adm-zip');

const app = express();
const PORT = process.env.PORT || 10000;

/* ==========================
   Basic App Middleware
   ========================== */
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

/* ==========================
   Simple Health
   ========================== */
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Chatti Platform API is running' });
});

/* ==========================
   Auth (hash-only login)
   ========================== */
// constant-time compare for hex strings
function constantTimeEqualHex(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  const ab = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

const APP_JWT_SECRET = process.env.JWT_SECRET || ('change-me-' + Date.now());

app.post('/api/login', async (req, res) => {
  try {
    const { email, passHash } = req.body; // passHash is SHA-256 hex from client
    const okEmail = !!email && email.toLowerCase() === (process.env.ADMIN_USER_EMAIL || '').toLowerCase();
    const okHash = !!passHash && constantTimeEqualHex(passHash, process.env.ADMIN_PASS_SHA256 || '');

    if (!okEmail || !okHash) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    const token = jwt.sign({ sub: email, role: 'admin' }, APP_JWT_SECRET, { expiresIn: '12h' });
    res.json({ success: true, token });
  } catch (e) {
    res.status(500).json({ success: false, message: 'Login error' });
  }
});

// app token check
function authenticateToken(req, res, next) {
  const header = req.headers.authorization || '';
  const [, token] = header.split(' ');
  if (!token) return res.status(401).json({ success: false, message: 'Missing token' });
  try {
    const payload = jwt.verify(token, APP_JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid/expired token' });
  }
}

/* ==========================
   Vonage JWT (RS256) for Reports v2
   ========================== */
function generateVonageJWT() {
  const applicationId = process.env.VONAGE_APPLICATION_ID;
  const privateKeyPem = process.env.VONAGE_PRIVATE_KEY; // full PEM

  if (!applicationId || !privateKeyPem) return null;

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    application_id: applicationId,
    iat: now,
    exp: now + 10 * 60, // 10 minutes
    jti: crypto.randomBytes(12).toString('hex'),
  };

  // Vonage expects RS256 with the App private key
  return jwt.sign(payload, privateKeyPem, { algorithm: 'RS256' });
}

/* ==========================
   Reports helpers (ASYNC ZIP)
   ========================== */

// Step 1: create async report (across sub-accounts)
async function createAsyncReport(headers, dateStart, dateEnd) {
  const body = {
    product: 'SMS',
    // Omit account_id to aggregate across subaccounts
    date_start: `${dateStart}T00:00:00Z`,
    date_end:   `${dateEnd}T23:59:59Z`,
    direction: 'outbound',
    include_subaccounts: true
  };

  const url = 'https://api.nexmo.com/v2/reports/async';
  const r = await axios.post(url, body, { headers, timeout: 30000 });
  return r.data?.request_id || r.data?.id;
}

// Step 2: poll status
async function pollAsyncReport(headers, requestId, timeoutMs = 10 * 60 * 1000) {
  const statusUrl = `https://api.nexmo.com/v2/reports/async/${requestId}`;
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    await new Promise(r => setTimeout(r, 5000));
    const s = await axios.get(statusUrl, { headers, timeout: 30000 });
    const state = s.data?.status || s.data?.state;

    if (/completed|complete|success/i.test(state)) {
      return s.data?.download_url || s.data?.links?.download_url;
    }
    if (/failed|error/i.test(state)) {
      const detail = s.data?.detail || s.data?.message || state;
      throw new Error(`Async report failed: ${detail}`);
    }
  }
  throw new Error('Async report timed out');
}

// Step 3: download ZIP + extract JSON/CSV
async function downloadAndExtractZip(headers, url) {
  const dl = await axios.get(url, {
    headers,
    responseType: 'arraybuffer',
    timeout: 180000
  });

  const zip = new AdmZip(Buffer.from(dl.data));
  const entries = zip.getEntries();
  let records = [];

  for (const e of entries) {
    const name = e.entryName.toLowerCase();
    const buf = e.getData();
    const text = buf.toString('utf8');

    if (name.endsWith('.json')) {
      const parsed = JSON.parse(text);
      const arr = parsed.records || parsed.items || parsed;
      if (Array.isArray(arr)) records.push(...arr);
    } else if (name.endsWith('.csv')) {
      const lines = text.trim().split(/\r?\n/);
      if (lines.length) {
        const headersCsv = lines[0].split(',');
        for (let i = 1; i < lines.length; i++) {
          // naive CSV split (ok for Vonage default CSV)
          const cols = lines[i].split(',');
          const rec = {};
          headersCsv.forEach((h, idx) => { rec[h] = cols[idx]; });
          records.push(rec);
        }
      }
    }
  }
  return records;
}

/* ==========================
   Sync fallback (master account only)
   ========================== */
async function fetchSyncReportData(headers, dateStart, dateEnd) {
  try {
    console.log('\n=== SYNC Reports (master only) ===');
    const body = {
      product: 'SMS',
      // master account only — do NOT include_subaccounts (403)
      date_start: `${dateStart}T00:00:00Z`,
      date_end:   `${dateEnd}T23:59:59Z`,
      direction: 'outbound'
    };
    const r = await axios.post('https://api.nexmo.com/v2/reports', body, { headers, timeout: 45000 });
    return r.data?.records || [];
  } catch (e) {
    console.error('Sync method error:', e?.response?.data || e.message);
    return [];
  }
}

/* ==========================
   Aggregation helper
   ========================== */
function asNumber(x) {
  if (x == null) return 0;
  if (typeof x === 'number') return x;
  const n = parseFloat(x);
  return Number.isFinite(n) ? n : 0;
}

/**
 * Accepts heterogeneous records (JSON or CSV-like) and returns:
 *  - total, inbound, outbound
 *  - byCountry, bySubAccount, byDate
 *  - totalCost
 */
function processRecords(records) {
  const out = {
    total: 0,
    inbound: 0,
    outbound: 0,
    byCountry: {},      // { AU: { count, cost }, ... } (we'll try country name or code)
    bySubAccount: {},   // { apiKey: { accountId, accountName, count, cost, byCountry: {} } }
    byDate: {},         // { 'YYYY-MM-DD': count }
    totalCost: 0
  };

  for (const r of records) {
    // Field names vary between JSON and CSV — normalize carefully
    const direction = (r.direction || r.Direction || '').toString().toLowerCase();
    const dateRaw   = r.client_ref_date || r.date || r['Date'] || r['date'] || r.timestamp || r['Timestamp'] || '';
    const accountId = r.account_id || r['account_id'] || r['Account ID'] || r.api_key || r['API Key'] || 'master';
    const accountName = r.account_name || r['Account Name'] || accountId;

    // country may be ISO or name
    const country = r.mccmnc_country || r.country || r['Country'] || r.country_name || r['Country Name'] || 'Other';

    // price/cost field guessing
    const priceFields = [
      'price', 'total_price', 'cost', 'charge', 'amount', 'rate', 'total_amount', 'usage'
    ];
    let cost = 0;
    for (const f of priceFields) {
      if (r[f] != null) { cost = asNumber(r[f]); break; }
      const alt = r[f.toUpperCase()] ?? r[camelToTitle(f)];
      if (alt != null) { cost = asNumber(alt); break; }
    }

    // count (each record is a message)
    const count = 1;

    // top-level totals
    out.total += count;
    if (direction === 'inbound') out.inbound += count;
    else out.outbound += count;

    // date bucket (YYYY-MM-DD if possible)
    const day = (typeof dateRaw === 'string' && dateRaw.length >= 10)
      ? dateRaw.slice(0,10)
      : '';

    if (day) out.byDate[day] = (out.byDate[day] || 0) + count;

    // country bucket
    if (!out.byCountry[country]) out.byCountry[country] = { count: 0, cost: 0 };
    out.byCountry[country].count += count;
    out.byCountry[country].cost += cost;

    // subaccount bucket
    if (!out.bySubAccount[accountId]) {
      out.bySubAccount[accountId] = { accountId, accountName, count: 0, cost: 0, byCountry: {} };
    }
    out.bySubAccount[accountId].count += count;
    out.bySubAccount[accountId].cost  += cost;

    if (!out.bySubAccount[accountId].byCountry[country]) {
      out.bySubAccount[accountId].byCountry[country] = { count: 0, cost: 0 };
    }
    out.bySubAccount[accountId].byCountry[country].count += count;
    out.bySubAccount[accountId].byCountry[country].cost  += cost;

    out.totalCost += cost;
  }

  return out;
}

function camelToTitle(s) {
  return s.replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase());
}

/* ==========================
   Utility
   ========================== */
function monthToRange(yyyyMm) {
  const [yStr, mStr] = (yyyyMm || '').split('-');
  const y = parseInt(yStr, 10);
  const m = parseInt(mStr, 10);
  if (!y || !m) throw new Error('Invalid month; expected YYYY-MM');
  const start = new Date(Date.UTC(y, m - 1, 1));
  const end = new Date(Date.UTC(y, m, 0)); // last day of month
  const fmt = d => d.toISOString().slice(0,10);
  return { start: fmt(start), end: fmt(end) };
}

/* ==========================
   Test + helper endpoints
   ========================== */

// Quick sanity: are Reports creds present?
app.get('/api/vonage/test-reports', authenticateToken, (req, res) => {
  const missing = [];
  if (!process.env.VONAGE_APPLICATION_ID) missing.push('VONAGE_APPLICATION_ID');
  if (!process.env.VONAGE_PRIVATE_KEY) missing.push('VONAGE_PRIVATE_KEY');
  res.json({ success: missing.length === 0, missing });
});

// Optional: simple Vonage balance check with Basic (if you set API KEY/SECRET)
app.get('/api/vonage/test', authenticateToken, async (req, res) => {
  try {
    const { VONAGE_API_KEY, VONAGE_API_SECRET } = process.env;
    if (!VONAGE_API_KEY || !VONAGE_API_SECRET) {
      return res.json({ success: false, message: 'API key/secret not set (optional test endpoint).' });
    }
    const auth = Buffer.from(`${VONAGE_API_KEY}:${VONAGE_API_SECRET}`).toString('base64');
    const r = await axios.get('https://rest.nexmo.com/account/get-balance', {
      headers: { Authorization: `Basic ${auth}` },
      params: { api_key: VONAGE_API_KEY, api_secret: VONAGE_API_SECRET },
      timeout: 15000
    });
    res.json({ success: true, balance: r.data?.value, autoReload: r.data?.auto_reload });
  } catch (e) {
    res.json({ success: false, error: e?.response?.data || e.message });
  }
});

/* ==========================
   MAIN: SMS usage
   ========================== */
app.get('/api/vonage/usage/sms', authenticateToken, async (req, res) => {
  try {
    const month = (req.query.month || new Date().toISOString().slice(0,7)).trim();
    const { start: dateStart, end: dateEnd } = monthToRange(month);

    // Build Reports JWT headers
    const vonageJwt = generateVonageJWT();
    if (!vonageJwt) {
      return res.json({
        success: false,
        message: 'Missing VONAGE_APPLICATION_ID or VONAGE_PRIVATE_KEY.',
        support: 'Set both env vars; private key must be full PEM with BEGIN/END and newlines.'
      });
    }
    const headers = {
      'Authorization': `Bearer ${vonageJwt}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    };

    console.log('=== ASYNC REPORT: create → poll → download ===');
    console.log(`Range: ${dateStart} .. ${dateEnd}`);

    let records = [];
    try {
      const requestId = await createAsyncReport(headers, dateStart, dateEnd);
      console.log('Request ID:', requestId);
      const downloadUrl = await pollAsyncReport(headers, requestId);
      console.log('Download URL:', downloadUrl);
      records = await downloadAndExtractZip(headers, downloadUrl);
      console.log('Async records:', records.length);
    } catch (e) {
      console.error('Async flow failed:', e?.response?.data || e.message);
      // Fallback to sync (master only)
      records = await fetchSyncReportData(headers, dateStart, dateEnd);
      console.log('Sync fallback records:', records.length);
    }

    const agg = processRecords(records);
    const payload = {
      success: true,
      data: {
        total: agg.total,
        outbound: agg.outbound,
        inbound: agg.inbound,
        byCountry: agg.byCountry,
        bySubAccount: agg.bySubAccount,
        byDate: agg.byDate,
        totalCost: agg.totalCost,
        currentMonth: month
      },
      month,
      dateRange: `${dateStart} to ${dateEnd}`,
      recordCount: records.length
    };

    if (records.length === 0) {
      payload.message = 'No SMS data retrieved. Check Render logs for async status or permission errors.';
      payload.support = 'If this persists, send the create/poll responses from the logs to Vonage support.';
    }

    res.json(payload);
  } catch (e) {
    res.json({
      success: false,
      message: 'Usage fetch failed',
      error: e?.response?.data || e.message
    });
  }
});

// Convenience: current month
app.get('/api/vonage/usage/current', authenticateToken, (req, res) => {
  const month = new Date().toISOString().slice(0,7);
  res.redirect(302, `/api/vonage/usage/sms?month=${month}`);
});

/* ==========================
   Start
   ========================== */
app.listen(PORT, () => {
  console.log('========================================');
  console.log('Chatti Platform Server Starting...');
  console.log('========================================');
  console.log('Port:', PORT);
  console.log('Environment:', process.env.NODE_ENV || 'development');
  console.log('URL: http://localhost:' + PORT);
  console.log('=== CONFIGURATION STATUS ===');
  console.log('✅ JWT_SECRET:', process.env.JWT_SECRET ? 'Configured' : 'Missing');
  console.log('=== VONAGE API STATUS ===');
  console.log('✅ VONAGE_APPLICATION_ID:', process.env.VONAGE_APPLICATION_ID ? 'Configured' : 'Missing');
  console.log('========================================');
});
