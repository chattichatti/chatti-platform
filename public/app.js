// app.js - Frontend JavaScript for Chatti Platform
// This version works with the online hosted server

// No need to specify API_URL since we're on the same server
const API_URL = ''; // Empty string means same server

// Global state
let currentUser = null;
let currentView = 'login';

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    // Set current month in selectors
    const now = new Date();
    const currentMonth = now.toISOString().slice(0, 7);
    const monthSelector = document.getElementById('monthSelector');
    if (monthSelector) {
        monthSelector.value = currentMonth;
    }
});

// Login function
async function login() {
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    const role = document.getElementById('loginRole').value;
    
    if (!email || !password) {
        alert('Please enter email and password');
        return;
    }
    
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, role })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentUser = data.user;
            localStorage.setItem('token', data.token);
            
            if (role === 'admin') {
                showAdminDashboard();
            } else {
                showCustomerDashboard();
            }
        } else {
            alert('Login failed: ' + data.message);
        }
    } catch (error) {
        console.error('Login error:', error);
        alert('Login failed. Please try again.');
    }
}

// Logout function
function logout() {
    currentUser = null;
    localStorage.removeItem('token');
    document.getElementById('loginScreen').classList.remove('hidden');
    document.getElementById('adminDashboard').classList.add('hidden');
    document.getElementById('customerDashboard').classList.add('hidden');
}

// Show Admin Dashboard
function showAdminDashboard() {
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('adminDashboard').classList.remove('hidden');
    loadAdminData();
}

// Show Customer Dashboard
function showCustomerDashboard() {
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('customerDashboard').classList.remove('hidden');
    loadCustomerData();
}

// Admin section navigation
function showAdminSection(section) {
    // Hide all sections
    document.querySelectorAll('.admin-section').forEach(el => {
        el.classList.add('hidden');
    });
    // Show selected section
    document.getElementById(`admin-${section}`).classList.remove('hidden');
    
    // Load section-specific data
    if (section === 'customers') {
        loadCustomers();
    } else if (section === 'products') {
        loadProductMappings();
    }
}

// Load Admin Data
async function loadAdminData() {
    try {
        // Fetch SMS usage from API
        const response = await fetch('/api/vonage/usage/sms');
        const result = await response.json();
        
        if (result.success) {
            const usage = result.data;
            
            // Update dashboard stats
            document.getElementById('totalSMSMonth').textContent = usage.total.toLocaleString();
            document.getElementById('inboundSMS').textContent = usage.inbound.toLocaleString();
            document.getElementById('outboundSMS').textContent = usage.outbound.toLocaleString();
            
            // Update country table
            const countryTable = document.getElementById('countryUsageTable');
            countryTable.innerHTML = usage.byCountry.map(country => `
                <tr class="border-b">
                    <td class="px-4 py-2">
                        <span class="font-medium">${country.country}</span>
                        <span class="text-gray-500 text-sm ml-2">${country.code}</span>
                    </td>
                    <td class="px-4 py-2">${country.inbound.toLocaleString()}</td>
                    <td class="px-4 py-2">${country.outbound.toLocaleString()}</td>
                    <td class="px-4 py-2 font-medium">${(country.inbound + country.outbound).toLocaleString()}</td>
                </tr>
            `).join('');
        }
        
        // Load customers count
        const customersResponse = await fetch('/api/customers');
        const customersResult = await customersResponse.json();
        if (customersResult.success) {
            document.getElementById('activeCustomers').textContent = customersResult.data.length;
        }
    } catch (error) {
        console.error('Error loading admin data:', error);
    }
}

// Load Customers
async function loadCustomers() {
    try {
        const response = await fetch('/api/customers');
        const result = await response.json();
        
        if (result.success) {
            const customerTable = document.getElementById('customerTable');
            customerTable.innerHTML = result.data.map(customer => {
                const numbersList = Object.entries(customer.numbers || {})
                    .map(([country, count]) => `${country}: ${count}`)
                    .join(', ');
                
                return `
                    <tr class="border-b hover:bg-gray-50">
                        <td class="px-4 py-2">
                            <div class="font-medium">${customer.name}</div>
                        </td>
                        <td class="px-4 py-2 text-sm">${customer.vonageAccount}</td>
                        <td class="px-4 py-2 text-sm">
                            ${customer.xeroContact ? 
                                `<span class="text-green-600">${customer.xeroContact}</span>` : 
                                '<span class="text-red-600">Not linked</span>'}
                        </td>
                        <td class="px-4 py-2">${customer.currentSMS?.toLocaleString() || '0'}</td>
                        <td class="px-4 py-2 text-sm">${numbersList || 'None'}</td>
                        <td class="px-4 py-2">
                            <button onclick="viewCustomerDetails(${customer.id})" class="text-blue-600 hover:underline text-sm">
                                View Details
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');
        }
    } catch (error) {
        console.error('Error loading customers:', error);
    }
}

// Load Customer Data
async function loadCustomerData() {
    try {
        // For demo, using customer ID 1
        const response = await fetch('/api/vonage/usage/customer/1');
        const result = await response.json();
        
        if (result.success) {
            const usage = result.data;
            
            // Calculate previous month (demo data)
            const previous = 4200;
            const trend = ((usage.total - previous) / previous * 100).toFixed(1);
            
            document.getElementById('customerCurrentSMS').textContent = usage.total.toLocaleString();
            document.getElementById('customerPreviousSMS').textContent = previous.toLocaleString();
            document.getElementById('customerTrend').textContent = trend > 0 ? `+${trend}%` : `${trend}%`;
            
            // Update usage table
            const usageTable = document.getElementById('customerUsageTable');
            const currentMonth = new Date().toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
            const prevMonth = new Date(Date.now() - 30*24*60*60*1000).toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
            
            usageTable.innerHTML = `
                <tr class="border-b">
                    <td class="px-4 py-2">${currentMonth}</td>
                    <td class="px-4 py-2">${usage.inbound.toLocaleString()}</td>
                    <td class="px-4 py-2">${usage.outbound.toLocaleString()}</td>
                    <td class="px-4 py-2 font-medium">${usage.total.toLocaleString()}</td>
                </tr>
                <tr class="border-b">
                    <td class="px-4 py-2">${prevMonth}</td>
                    <td class="px-4 py-2">1,000</td>
                    <td class="px-4 py-2">3,200</td>
                    <td class="px-4 py-2 font-medium">4,200</td>
                </tr>
            `;
        }
    } catch (error) {
        console.error('Error loading customer data:', error);
    }
}

// Load month data
async function loadMonthData() {
    const month = document.getElementById('monthSelector').value;
    const historicalDiv = document.getElementById('historicalData');
    
    try {
        const response = await fetch(`/api/vonage/usage/sms?month=${month}`);
        const result = await response.json();
        
        if (result.success) {
            historicalDiv.innerHTML = `
                <div class="text-left">
                    <p class="font-medium mb-2">SMS Usage for ${month}</p>
                    <div class="grid grid-cols-3 gap-4">
                        <div>
                            <span class="text-gray-600">Total:</span>
                            <span class="font-bold ml-2">${result.data.total.toLocaleString()}</span>
                        </div>
                        <div>
                            <span class="text-gray-600">Inbound:</span>
                            <span class="font-bold ml-2">${result.data.inbound.toLocaleString()}</span>
                        </div>
                        <div>
                            <span class="text-gray-600">Outbound:</span>
                            <span class="font-bold ml-2">${result.data.outbound.toLocaleString()}</span>
                        </div>
                    </div>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error loading month data:', error);
        historicalDiv.innerHTML = '<p class="text-red-600">Error loading data</p>';
    }
}

// View customer details
function viewCustomerDetails(customerId) {
    alert(`Customer details for ID: ${customerId} - This will show detailed usage breakdown`);
}

// Show link customer modal
function showLinkCustomerModal() {
    const vonageAccount = prompt('Enter Vonage Account ID:');
    const xeroContact = prompt('Enter Xero Contact ID:');
    const customerName = prompt('Enter Customer Name:');
    
    if (vonageAccount && xeroContact && customerName) {
        linkCustomerAccounts(vonageAccount, xeroContact, customerName);
    }
}

// Link customer accounts
async function linkCustomerAccounts(vonageAccount, xeroContact, customerName) {
    try {
        const response = await fetch('/api/customers/link', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vonageAccount, xeroContact, customerName })
        });
        
        const result = await response.json();
        if (result.success) {
            alert('Customer accounts linked successfully!');
            loadCustomers();
        }
    } catch (error) {
        console.error('Error linking accounts:', error);
        alert('Failed to link accounts');
    }
}

// Show add product modal
function showAddProductModal() {
    alert('Add Product Mapping Modal - Map Vonage products to Xero items');
}

// Load product mappings
async function loadProductMappings() {
    try {
        const response = await fetch('/api/products/mappings');
        const result = await response.json();
        
        if (result.success) {
            const table = document.getElementById('productMappingTable');
            table.innerHTML = result.data.map(mapping => `
                <tr class="border-b">
                    <td class="px-2 py-1">${mapping.vonageProduct}</td>
                    <td class="px-2 py-1">${mapping.xeroItem}</td>
                    <td class="px-2 py-1">${mapping.type}</td>
                </tr>
            `).join('');
        }
    } catch (error) {
        console.error('Error loading product mappings:', error);
    }
}

// Generate draft invoices
async function generateDraftInvoices() {
    try {
        const month = document.getElementById('monthSelector')?.value || new Date().toISOString().slice(0, 7);
        
        const response = await fetch('/api/billing/generate-invoices', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ month })
        });
        
        const result = await response.json();
        
        if (result.success) {
            const draftDiv = document.getElementById('draftInvoicesTable');
            draftDiv.innerHTML = `
                <div class="text-left">
                    <p class="text-green-600 font-medium mb-3">✓ Generated ${result.data.length} draft invoices</p>
                    <table class="w-full">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Customer</th>
                                <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Invoice #</th>
                                <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Amount</th>
                                <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                                <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${result.data.map(invoice => `
                                <tr class="border-b">
                                    <td class="px-4 py-2">${invoice.customer}</td>
                                    <td class="px-4 py-2">${invoice.id}</td>
                                    <td class="px-4 py-2">$${invoice.amount.toFixed(2)}</td>
                                    <td class="px-4 py-2"><span class="text-yellow-600">Draft</span></td>
                                    <td class="px-4 py-2">
                                        <button class="text-blue-600 hover:underline text-sm mr-2">View</button>
                                        <button onclick="sendToXero('${invoice.id}')" class="text-green-600 hover:underline text-sm">Send to Xero</button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error generating invoices:', error);
        alert('Failed to generate invoices');
    }
}

// Send invoice to Xero
async function sendToXero(invoiceId) {
    alert(`Sending invoice ${invoiceId} to Xero...`);
    // Implementation will be added when Xero is fully connected
}

// Save Vonage settings
async function saveVonageSettings() {
    const apiKey = document.getElementById('vonageApiKey').value;
    const apiSecret = document.getElementById('vonageApiSecret').value;
    
    if (apiKey && apiSecret) {
        alert('Vonage API settings will be saved on the server');
        // These should be saved as environment variables on the server
    } else {
        alert('Please enter both API Key and Secret');
    }
}

// Connect to Xero
async function connectXero() {
    try {
        const response = await fetch('/api/xero/auth');
        const result = await response.json();
        
        if (result.authUrl) {
            // Redirect to Xero for authorization
            window.location.href = result.authUrl;
        }
    } catch (error) {
        console.error('Error connecting to Xero:', error);
        alert('Failed to connect to Xero');
    }
}

// Check for Xero callback
window.addEventListener('load', function() {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('xero') === 'connected') {
        alert('Xero connected successfully!');
        window.history.replaceState({}, document.title, '/');
    } else if (urlParams.get('xero') === 'error') {
        alert('Failed to connect to Xero. Please try again.');
        window.history.replaceState({}, document.title, '/');
    }
});