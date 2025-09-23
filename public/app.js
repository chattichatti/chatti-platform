// public/app.js - CORRECT VERSION that actually authenticates

// Store auth token
let authToken = null;

// Login function that ACTUALLY calls the server
async function login() {
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    const role = document.getElementById('loginRole').value;
    
    if (!email || !password) {
        alert('Please enter email and password');
        return;
    }
    
    try {
        // ACTUALLY CALL THE SERVER
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json' 
            },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            // Store token
            authToken = data.token;
            localStorage.setItem('authToken', authToken);
            
            // Hide login screen
            document.getElementById('loginScreen').classList.add('hidden');
            
            // Show appropriate dashboard
            if (data.user.role === 'admin') {
                document.getElementById('adminDashboard').classList.remove('hidden');
                loadAdminData();
            } else {
                document.getElementById('customerDashboard').classList.remove('hidden');
                loadCustomerData();
            }
        } else {
            // REJECT invalid credentials
            alert(data.message || 'Invalid email or password');
        }
    } catch (error) {
        console.error('Login error:', error);
        alert('Login failed. Please check your credentials.');
    }
}

// Logout function
function logout() {
    authToken = null;
    localStorage.removeItem('authToken');
    document.getElementById('loginScreen').classList.remove('hidden');
    document.getElementById('adminDashboard').classList.add('hidden');
    document.getElementById('customerDashboard').classList.add('hidden');
}

// Admin section navigation
function showAdminSection(section) {
    document.querySelectorAll('.admin-section').forEach(el => {
        el.style.display = 'none';
    });
    const sectionEl = document.getElementById(`admin-${section}`);
    if (sectionEl) {
        sectionEl.style.display = 'block';
    }
}

// Load admin data with authentication
async function loadAdminData() {
    try {
        const response = await fetch('/api/vonage/usage/sms', {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            const result = await response.json();
            if (result.success) {
                document.getElementById('totalSMSMonth').textContent = result.data.total.toLocaleString();
                document.getElementById('inboundSMS').textContent = result.data.inbound.toLocaleString();
                document.getElementById('outboundSMS').textContent = result.data.outbound.toLocaleString();
                document.getElementById('activeCustomers').textContent = '24';
                
                // Update country table
                const countryTable = document.getElementById('countryUsageTable');
                countryTable.innerHTML = result.data.byCountry.map(country => `
                    <tr class="border-b">
                        <td class="px-4 py-2">${country.country} ${country.code}</td>
                        <td class="px-4 py-2">${country.inbound.toLocaleString()}</td>
                        <td class="px-4 py-2">${country.outbound.toLocaleString()}</td>
                        <td class="px-4 py-2 font-bold">${(country.inbound + country.outbound).toLocaleString()}</td>
                    </tr>
                `).join('');
            }
        } else if (response.status === 401) {
            alert('Session expired. Please login again.');
            logout();
        }
    } catch (error) {
        console.error('Error loading admin data:', error);
    }
}

// Other functions
function loadCustomerData() {
    document.getElementById('customerCurrentSMS').textContent = '5,430';
    document.getElementById('customerPreviousSMS').textContent = '4,200';
    document.getElementById('customerTrend').textContent = '+29.3%';
}

function loadCustomers() {
    // Customer loading code
}

function showLinkCustomerModal() {
    alert('Link Customer Modal - Coming soon');
}

function showAddProductModal() {
    alert('Add Product Mapping - Coming soon');
}

function generateDraftInvoices() {
    alert('Generating draft invoices...');
}

function saveVonageSettings() {
    alert('Vonage settings saved');
}

function connectXero() {
    alert('Connecting to Xero...');
}

function loadMonthData() {
    const month = document.getElementById('monthSelector').value;
    if (month) {
        document.getElementById('historicalData').innerHTML = 'Data for ' + month;
    }
}

// Check if already logged in on page load
document.addEventListener('DOMContentLoaded', function() {
    const savedToken = localStorage.getItem('authToken');
    if (savedToken) {
        authToken = savedToken;
        // Optionally auto-login if token exists
    }
});