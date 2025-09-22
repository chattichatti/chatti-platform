// app.js - Frontend JavaScript for Chatti Platform

// Login function
function login() {
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    const role = document.getElementById('loginRole').value;
    
    if (!email || !password) {
        alert('Please enter email and password');
        return;
    }
    
    // Hide login screen
    document.getElementById('loginScreen').classList.add('hidden');
    
    // Show appropriate dashboard
    if (role === 'admin') {
        document.getElementById('adminDashboard').classList.remove('hidden');
        loadAdminData();
    } else {
        document.getElementById('customerDashboard').classList.remove('hidden');
        loadCustomerData();
    }
}

// Logout function
function logout() {
    document.getElementById('loginScreen').classList.remove('hidden');
    document.getElementById('adminDashboard').classList.add('hidden');
    document.getElementById('customerDashboard').classList.add('hidden');
}

// Show admin sections
function showAdminSection(section) {
    // Hide all sections
    document.querySelectorAll('.admin-section').forEach(el => {
        el.style.display = 'none';
    });
    // Show selected section
    const sectionEl = document.getElementById(`admin-${section}`);
    if (sectionEl) {
        sectionEl.style.display = 'block';
    }
    
    // Load section-specific data
    if (section === 'customers') {
        loadCustomers();
    }
}

// Load admin dashboard data
function loadAdminData() {
    // Set demo data
    document.getElementById('totalSMSMonth').textContent = '45,678';
    document.getElementById('inboundSMS').textContent = '12,345';
    document.getElementById('outboundSMS').textContent = '33,333';
    document.getElementById('activeCustomers').textContent = '24';
    
    // Load country usage table
    document.getElementById('countryUsageTable').innerHTML = `
        <tr class="border-b">
            <td class="px-4 py-2"><span class="font-medium">Australia</span> <span class="text-gray-500 text-sm">+61</span></td>
            <td class="px-4 py-2">5,000</td>
            <td class="px-4 py-2">15,000</td>
            <td class="px-4 py-2 font-bold">20,000</td>
        </tr>
        <tr class="border-b">
            <td class="px-4 py-2"><span class="font-medium">United States</span> <span class="text-gray-500 text-sm">+1</span></td>
            <td class="px-4 py-2">3,000</td>
            <td class="px-4 py-2">8,000</td>
            <td class="px-4 py-2 font-bold">11,000</td>
        </tr>
        <tr class="border-b">
            <td class="px-4 py-2"><span class="font-medium">United Kingdom</span> <span class="text-gray-500 text-sm">+44</span></td>
            <td class="px-4 py-2">2,000</td>
            <td class="px-4 py-2">6,000</td>
            <td class="px-4 py-2 font-bold">8,000</td>
        </tr>
        <tr class="border-b">
            <td class="px-4 py-2"><span class="font-medium">Singapore</span> <span class="text-gray-500 text-sm">+65</span></td>
            <td class="px-4 py-2">2,345</td>
            <td class="px-4 py-2">4,333</td>
            <td class="px-4 py-2 font-bold">6,678</td>
        </tr>
    `;
}

// Load customers
function loadCustomers() {
    document.getElementById('customerTable').innerHTML = `
        <tr class="border-b hover:bg-gray-50">
            <td class="px-4 py-2">
                <div class="font-medium">Acme Corp</div>
                <div class="text-sm text-gray-500">contact@acme.com</div>
            </td>
            <td class="px-4 py-2 text-sm">VON-12345</td>
            <td class="px-4 py-2 text-sm">
                <span class="text-green-600">XERO-ABC123</span>
            </td>
            <td class="px-4 py-2">5,430</td>
            <td class="px-4 py-2 text-sm">AU: 3, US: 2</td>
            <td class="px-4 py-2">
                <button class="text-blue-600 hover:underline text-sm">View Details</button>
            </td>
        </tr>
        <tr class="border-b hover:bg-gray-50">
            <td class="px-4 py-2">
                <div class="font-medium">TechStart Inc</div>
                <div class="text-sm text-gray-500">billing@techstart.com</div>
            </td>
            <td class="px-4 py-2 text-sm">VON-12346</td>
            <td class="px-4 py-2 text-sm">
                <span class="text-green-600">XERO-DEF456</span>
            </td>
            <td class="px-4 py-2">2,100</td>
            <td class="px-4 py-2 text-sm">AU: 5, SG: 2</td>
            <td class="px-4 py-2">
                <button class="text-blue-600 hover:underline text-sm">View Details</button>
            </td>
        </tr>
        <tr class="border-b hover:bg-gray-50">
            <td class="px-4 py-2">
                <div class="font-medium">Global Solutions</div>
                <div class="text-sm text-gray-500">accounts@global.com</div>
            </td>
            <td class="px-4 py-2 text-sm">VON-12347</td>
            <td class="px-4 py-2 text-sm">
                <span class="text-red-600">Not linked</span>
            </td>
            <td class="px-4 py-2">8,900</td>
            <td class="px-4 py-2 text-sm">AU: 10, US: 5, UK: 3</td>
            <td class="px-4 py-2">
                <button class="text-blue-600 hover:underline text-sm">View Details</button>
            </td>
        </tr>
    `;
}

// Load customer data
function loadCustomerData() {
    document.getElementById('customerCurrentSMS').textContent = '5,430';
    document.getElementById('customerPreviousSMS').textContent = '4,200';
    document.getElementById('customerTrend').textContent = '+29.3%';
    
    // Load usage table
    document.getElementById('customerUsageTable').innerHTML = `
        <tr class="border-b">
            <td class="px-4 py-2">November 2024</td>
            <td class="px-4 py-2">1,230</td>
            <td class="px-4 py-2">4,200</td>
            <td class="px-4 py-2 font-bold">5,430</td>
        </tr>
        <tr class="border-b">
            <td class="px-4 py-2">October 2024</td>
            <td class="px-4 py-2">1,000</td>
            <td class="px-4 py-2">3,200</td>
            <td class="px-4 py-2 font-bold">4,200</td>
        </tr>
    `;
}

// Modal functions
function showLinkCustomerModal() {
    const vonageAccount = prompt('Enter Vonage Account ID:');
    const xeroContact = prompt('Enter Xero Contact ID:');
    if (vonageAccount && xeroContact) {
        alert(`Linking Vonage Account ${vonageAccount} to Xero Contact ${xeroContact}`);
        loadCustomers();
    }
}

function showAddProductModal() {
    alert('Add Product Mapping - This will open a form to map Vonage products to Xero items');
}

// Generate invoices
function generateDraftInvoices() {
    const draftDiv = document.getElementById('draftInvoicesTable');
    draftDiv.innerHTML = `
        <div class="text-left">
            <p class="text-green-600 font-medium mb-3">✓ Draft invoices generated successfully</p>
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
                    <tr class="border-b">
                        <td class="px-4 py-2">Acme Corp</td>
                        <td class="px-4 py-2">INV-2024-001</td>
                        <td class="px-4 py-2">$543.00</td>
                        <td class="px-4 py-2"><span class="text-yellow-600">Draft</span></td>
                        <td class="px-4 py-2">
                            <button class="text-blue-600 hover:underline text-sm mr-2">View</button>
                            <button class="text-green-600 hover:underline text-sm">Send to Xero</button>
                        </td>
                    </tr>
                    <tr class="border-b">
                        <td class="px-4 py-2">TechStart Inc</td>
                        <td class="px-4 py-2">INV-2024-002</td>
                        <td class="px-4 py-2">$210.00</td>
                        <td class="px-4 py-2"><span class="text-yellow-600">Draft</span></td>
                        <td class="px-4 py-2">
                            <button class="text-blue-600 hover:underline text-sm mr-2">View</button>
                            <button class="text-green-600 hover:underline text-sm">Send to Xero</button>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    `;
}

// Settings functions
function saveVonageSettings() {
    const apiKey = document.getElementById('vonageApiKey').value;
    const apiSecret = document.getElementById('vonageApiSecret').value;
    if (apiKey && apiSecret) {
        alert('Vonage API settings saved successfully!');
    } else {
        alert('Please enter both API Key and Secret');
    }
}

function connectXero() {
    const clientId = document.getElementById('xeroClientId').value;
    const clientSecret = document.getElementById('xeroClientSecret').value;
    if (clientId && clientSecret) {
        alert('Redirecting to Xero for authorization...');
        // In production, this would redirect to Xero OAuth
    } else {
        alert('Please enter both Client ID and Secret');
    }
}

// Load month data
function loadMonthData() {
    const month = document.getElementById('monthSelector').value;
    if (month) {
        document.getElementById('historicalData').innerHTML = `
            <div class="text-left">
                <p class="font-medium mb-2">SMS Usage for ${month}</p>
                <div class="grid grid-cols-3 gap-4">
                    <div>
                        <span class="text-gray-600">Total:</span>
                        <span class="font-bold ml-2">38,450</span>
                    </div>
                    <div>
                        <span class="text-gray-600">Inbound:</span>
                        <span class="font-bold ml-2">10,230</span>
                    </div>
                    <div>
                        <span class="text-gray-600">Outbound:</span>
                        <span class="font-bold ml-2">28,220</span>
                    </div>
                </div>
            </div>
        `;
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    console.log('Chatti Platform loaded successfully');
    
    // Set current month in selector
    const now = new Date();
    const currentMonth = now.toISOString().slice(0, 7);
    const monthSelector = document.getElementById('monthSelector');
    if (monthSelector) {
        monthSelector.value = currentMonth;
    }
});

console.log('app.js loaded successfully');