// Replace the fetchAsyncReportData function in your server.js with this:

async function fetchAsyncReportData(headers, dateStart, dateEnd) {
    try {
        console.log('\n=== ASYNC REPORT PROCESS (Trying GET method) ===');
        
        // Build query parameters for GET request
        const params = new URLSearchParams({
            product: 'SMS',
            account_id: config.vonage.accountId,
            date_start: `${dateStart}T00:00:00Z`,
            date_end: `${dateEnd}T23:59:59Z`,
            direction: 'outbound',
            include_subaccounts: 'true',
            include_message: 'false',
            status: 'delivered'
        });
        
        const url = `https://api.nexmo.com/v2/reports/async?${params.toString()}`;
        console.log('Step 1: Creating async report with GET request');
        console.log('URL:', url);
        
        const createResponse = await axios.get(url, { headers, timeout: 30000 });
        
        const requestId = createResponse.data?.request_id;
        if (!requestId) {
            console.error('No request_id received:', createResponse.data);
            // Fall back to synchronous method
            return await fetchSyncReportData(headers, dateStart, dateEnd);
        }
        
        console.log(`Step 1 Success: Request ID = ${requestId}`);
        
        // Rest of the polling logic remains the same...
        const statusUrl = `https://api.nexmo.com/v2/reports/async/${requestId}`;
        let attempts = 0;
        const maxAttempts = 60;
        
        while (attempts < maxAttempts) {
            await new Promise(resolve => setTimeout(resolve, 5000));
            attempts++;
            
            const statusResponse = await axios.get(statusUrl, { headers, timeout: 30000 });
            const status = statusResponse.data?.status;
            
            console.log(`Poll attempt ${attempts}: Status = ${status}`);
            
            if (status === 'completed' || status === 'COMPLETED') {
                const downloadUrl = statusResponse.data?.download_url;
                
                if (downloadUrl) {
                    console.log('Step 3: Downloading ZIP file...');
                    const downloadResponse = await axios.get(downloadUrl, {
                        headers,
                        responseType: 'arraybuffer',
                        timeout: 120000
                    });
                    
                    const zip = new AdmZip(Buffer.from(downloadResponse.data));
                    const zipEntries = zip.getEntries();
                    
                    let allRecords = [];
                    zipEntries.forEach(entry => {
                        if (entry.entryName.endsWith('.json')) {
                            const jsonContent = entry.getData().toString('utf8');
                            const data = JSON.parse(jsonContent);
                            
                            if (data.records) {
                                allRecords = allRecords.concat(data.records);
                            } else if (Array.isArray(data)) {
                                allRecords = allRecords.concat(data);
                            }
                        }
                    });
                    
                    console.log(`Total records extracted = ${allRecords.length}`);
                    return allRecords;
                } else if (statusResponse.data?.records) {
                    return statusResponse.data.records;
                }
            } else if (status === 'failed' || status === 'FAILED') {
                console.error('Report generation failed');
                break;
            }
        }
        
        // If async fails, try sync
        return await fetchSyncReportData(headers, dateStart, dateEnd);
        
    } catch (error) {
        console.error('Async report error:', error.response?.status, error.response?.data || error.message);
        
        // Fall back to synchronous method
        if (error.response?.status === 405 || error.response?.status === 404) {
            console.log('Async not supported, trying synchronous method...');
            return await fetchSyncReportData(headers, dateStart, dateEnd);
        }
        
        return [];
    }
}

// Add this new function for synchronous fallback
async function fetchSyncReportData(headers, dateStart, dateEnd) {
    try {
        console.log('\n=== FALLBACK: Trying SYNCHRONOUS Reports API ===');
        
        const body = {
            product: 'SMS',
            account_id: config.vonage.accountId,
            date_start: `${dateStart}T00:00:00Z`,
            date_end: `${dateEnd}T23:59:59Z`,
            direction: 'outbound',
            include_subaccounts: true
        };
        
        console.log('Request body:', JSON.stringify(body, null, 2));
        
        const response = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000
        });
        
        console.log(`Sync response: ${response.data?.records?.length || 0} records`);
        
        if (response.data?.records) {
            return response.data.records;
        }
        
        // If still no data, try without include_subaccounts
        console.log('Trying without include_subaccounts...');
        delete body.include_subaccounts;
        
        const response2 = await axios.post('https://api.nexmo.com/v2/reports', body, {
            headers,
            timeout: 30000
        });
        
        console.log(`Response without include_subaccounts: ${response2.data?.records?.length || 0} records`);
        return response2.data?.records || [];
        
    } catch (error) {
        console.error('Sync method error:', error.response?.status, error.response?.data || error.message);
        return [];
    }
}