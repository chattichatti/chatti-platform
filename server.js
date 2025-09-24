// Replace the fetchSyncReportData function in your server.js with this:

async function fetchSyncReportData(headers, dateStart, dateEnd) {
    try {
        console.log('\n=== FALLBACK: Trying SYNCHRONOUS Reports API ===');
        
        // First try WITHOUT include_subaccounts (just master account)
        const bodyWithoutSubs = {
            product: 'SMS',
            account_id: config.vonage.accountId,
            date_start: `${dateStart}T00:00:00Z`,
            date_end: `${dateEnd}T23:59:59Z`,
            direction: 'outbound'
            // NO include_subaccounts parameter
        };
        
        console.log('Attempt 1: Master account only (no include_subaccounts)');
        console.log('Request body:', JSON.stringify(bodyWithoutSubs, null, 2));
        
        try {
            const response = await axios.post('https://api.nexmo.com/v2/reports', bodyWithoutSubs, {
                headers,
                timeout: 30000
            });
            
            console.log(`Master account response: ${response.data?.records?.length || 0} records`);
            
            if (response.data?.records && response.data.records.length > 0) {
                console.log('Found data for master account');
                return response.data.records;
            }
        } catch (e1) {
            console.error('Master account error:', e1.response?.status, e1.response?.data?.detail);
        }
        
        // If master account has no data, try to aggregate from individual sub-accounts
        console.log('\nAttempt 2: Fetching individual sub-accounts');
        const subAccounts = await fetchSubAccounts();
        
        if (subAccounts.length > 0) {
            console.log(`Found ${subAccounts.length} sub-accounts, checking first 5...`);
            let allRecords = [];
            let successCount = 0;
            
            // Test with first 5 sub-accounts
            const testAccounts = subAccounts.slice(0, 5);
            
            for (const subAccount of testAccounts) {
                try {
                    const subBody = {
                        product: 'SMS',
                        account_id: subAccount.api_key,  // Use sub-account's API key
                        date_start: `${dateStart}T00:00:00Z`,
                        date_end: `${dateEnd}T23:59:59Z`,
                        direction: 'outbound'
                    };
                    
                    const subResponse = await axios.post('https://api.nexmo.com/v2/reports', subBody, {
                        headers,
                        timeout: 10000
                    });
                    
                    if (subResponse.data?.records && subResponse.data.records.length > 0) {
                        allRecords = allRecords.concat(subResponse.data.records);
                        successCount++;
                        console.log(`✓ Sub-account ${subAccount.api_key}: ${subResponse.data.records.length} records`);
                    } else {
                        console.log(`○ Sub-account ${subAccount.api_key}: No SMS data`);
                    }
                } catch (subError) {
                    if (subError.response?.status === 403) {
                        console.log(`✗ Sub-account ${subAccount.api_key}: Forbidden`);
                    } else {
                        console.log(`✗ Sub-account ${subAccount.api_key}: Error ${subError.response?.status}`);
                    }
                }
            }
            
            console.log(`\nSummary: ${successCount}/${testAccounts.length} sub-accounts returned data`);
            console.log(`Total records collected: ${allRecords.length}`);
            
            if (allRecords.length > 0) {
                return allRecords;
            }
        }
        
        console.log('\nNo SMS data found in any account');
        return [];
        
    } catch (error) {
        console.error('Sync method error:', error.message);
        return [];
    }
}