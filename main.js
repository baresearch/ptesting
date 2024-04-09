const fs = require("fs");
const axios = require("axios");
const invariant = require("tiny-invariant");



/**
 * @INSTRUCTIONS => uses nodeJS 
 * 1. Set API key within code below to the "API_KEY" variable
 * 2. Install node and npm if not installed (can use brew)
 * 3. Run `npm install` to install npm packages
 * 4. Run 'npm start ipqs_progran` in your terminal
 * => this will create a .json file after it finishes analysi
 * 5. Check the .json file for the results of the analysis 
 * => The file generated with all the proxy data will have a "FINAL" suffix
 * appended to the file name
 * 
 * @important
 * - Free API on IPQS limits requests to 200 (?) per day, so if the
 * API was already used today, it might be good to wait fo ranothe rday
 * 
 */


// Insert API key here
const API_KEY = "";

// Do not change these
const SELECTED_PROXY_PROVIDER_TO_ANALYZE = "RYB"
const ANALYZER_API_NAME = "IPQS"


/**
 * Utility Functions
 */

function isNotUndefined(variable) {
    return variable !== undefined;
}


function sleep(milliseconds) {
    const date = Date.now();
    let currentDate = null;
    do {
        currentDate = Date.now();
    } while (currentDate - date < milliseconds);
}




/**
 * We do not want all the data returned by IPQS and use this to reformat
 * the HTTP response that we receive before further processing the proxy
 * results
 */
function extractsNecessaryDataFromIPQSResponse(ipqsResponse) {
    const data = ipqsResponse?.data;
    invariant(isNotUndefined(data), `data must be defined.`);
    
    const {
        fraud_score,
        region,
        city,
        ISP,
        organization,
        vpn,
        active_vpn,
        recent_abuse,
        bot_status,
        proxy, 
    } = data;
    
    return {
        fraud_score,
        region,
        city,
        ISP,
        organization,
        vpn,
        active_vpn,
        recent_abuse,
        bot_status,
        proxy, 
    };
}


/**
 * Generates the apprpriate IPQS URL endpoinit in order to test the proxy
 */
async function checkUserIPAgainstIPQS(ip_address,) {
	// var key = 'YOUR_API_KEY_HERE';
	var strictness = 1; // This optional parameter controls the level of strictness for the lookup. Setting this option higher will increase the chance for false-positives as well as the time needed to perform the IP analysis. Increase this setting if you still continue to see fraudulent IPs with our base setting (level 1 is recommended) or decrease this setting for faster lookups with less false-positives. Current options for this parameter are 0 (fastest), 1 (recommended), 2 (more strict), or 3 (strictest).
	var allow_public_access_points = 'true'; // Bypasses certain checks for IP addresses from education and research institutions, schools, and some corporate connections to better accommodate audiences that frequently use public connections. This value can be set to true to make the service less strict while still catching the riskiest connections.
	// var url = "https://www.ipqualityscore.com/api/json/ip/" + API_KEY + "/" + ip_address + "?user_agent=" + user_agent + "&user_language=" + language + "&strictness=" + strictness + "&allow_public_access_points=" + allow_public_access_points;
	var url = "https://www.ipqualityscore.com/api/json/ip/" + API_KEY + "/" + ip_address + "?strictness=" + strictness + "&allow_public_access_points=" + allow_public_access_points;
    console.log("🚀 ~ file: ipqs.js:22 ~ checkUserIPAgainstIPQS ~ url:", url)
	var result = await getIPQSURL(url);
	console.log("🚀 ~ file: ipqs.js:22 ~ checkUserIPAgainstIPQS ~ result:", result)
	if (result !== null) {
		return result;
	}
	else {
		// Throw error, no response received.
	}
}

/**
 * @EXAMPLE of Data returned by IPQS
 */

// data: {
//     success: true,
//     message: 'Success',
//     fraud_score: 100,
//     country_code: 'AU',
//     region: 'Western Australia',
//     city: 'Perth',
//     ISP: 'GSL Networks Pty',
//     ASN: 137409,
//     organization: 'NordVPN',
//     is_crawler: false,
//     timezone: 'Australia/Perth',
//     mobile: false,
//     host: '103.107.197.3',
//     proxy: true,
//     vpn: true,
//     tor: false,
//     active_vpn: true,
//     active_tor: false,
//     recent_abuse: true,
//     bot_status: true,
//     connection_type: 'Premium required.',
//     abuse_velocity: 'Premium required.',
//     zip_code: 'N/A',
//     latitude: -31.96430016,
//     longitude: 115.85949707,
//     request_id: 'K4t7HFQA57'
//   }

/**
 * Async request to IPQS servers
 */
async function getIPQSURL(url) {
	try {
		let response = await axios.get(url);
		console.log("🚀 ~ file: ipqs.js:37 ~ getIPQSURL ~ response:", response)
		return response;
	}
	catch (error) {
		return null;
	}
}


/**
 * Custom scoring function outsourced from IPQS code
 * @status Not used
 */
function validIPAddress(ip_address, user_agent, language) {
	let allowCrawlers = true; // Allow verified search engine crawlers from Google, Bing, Yahoo, DuckDuckGo, Baidu, Yandex, and similar major search engines. This setting is useful for preventing SEO penalties on front end placements.
	let lowerPenaltyForMobiles = false; // Prevents false positives for mobile devices - if set to true, this will only block VPN connections, Tor connections, and Fraud Scores greater than the minimum values set above for mobile devices. This setting is meant to provide greater accuracy for mobile devices due to mobile carriers frequently recycling and sharing mobile IP addresses. Please be sure to pass the "user_agent" (browser) for this feature to work. This setting ensures that the riskiest mobile connections are still blacklisted.
	
	let ip_result = checkUserIPAgainstIPQS(ip_address, user_agent, language);
	
	if (ip_result !== null) {
		if (allowCrawlers === true) {
			if (typeof ip_result !== 'undefined' && ip_result['is_crawler'] === true) {
				return false;
			}
		}
		if (ip_result['mobile'] === true && lowerPenaltyForMobiles === true) {
			if (typeof ip_result['fraud_score'] !== 'undefined' && ip_result['fraud_score'] >= fraudScoreMinBlockForMobiles) {
				return true;
			}
			else if (typeof ip_result['vpn'] !== 'undefined' && ip_result['vpn'] === true) {
				return ip_result['vpn'];
			}
			else if (typeof ip_result['tor'] !== 'undefined' && ip_result['tor'] === true) {
				return ip_result['tor'];
			}
			else {
				return false;
			}	
		}
		else {
			if (typeof ip_result['fraud_score'] !== 'undefined' &&  ip_result['fraud_score'] >= fraudScoreMinBlock) {
				return true;
			}
			else if (typeof ip_result['proxy'] !== 'undefined'){
				return ip_result['proxy'];
			}
			else {
				// Throw error, response is invalid.
			}
		}
	}
	else {
        return false;
	}
}


/**
 * Main function that makes request to IPQS serves and extracts the properties associated with 
 * the proxies in order to ultimately save them in local file
 */
async function scoreBatchOfProxies(listOfProxies, proxiesThatAreAlreadyConfirmedToBeFraudulent) {

    let countOfProxiesAnalyzed = 0;
    let counfOfProxiesDetectWithFakeBuffer = 0;
    let realCountOfProxiesDetected = 0;
    let overallProxyScoreAverageWithFakeBuffer = 0;
    let realOverallProxyScoreAverage = 0;

    const ispProxiesWhichFailed = [];
    const allProxyScores = [];
    let firstBatchOfProxiesSaved = false;
    let sanityBatchOfProxiesSaved = false;
    const date = new Date();
    const dateString = date.toISOString();

    for (let i=0; i<listOfProxies.length; i++) {
        const proxyMetadata = listOfProxies[i];
        const proxyScoreMetadata = await analyzeProxyMetadataScore(proxyMetadata);
        sleep(650);
        console.log("@scoreBatchOfProxies: proxyScoreMetadata: ", proxyScoreMetadata);
        const botStatus = proxyScoreMetadata.bot_status;
        const isProxy = proxyScoreMetadata.vpn || proxyScoreMetadata.active_vpn || proxyScoreMetadata.recent_abuse || proxyScoreMetadata.proxy;
        countOfProxiesAnalyzed++;
        allProxyScores.push(proxyScoreMetadata);
        console.log("🚀 ~ file: ipqs.js:316 ~ scoreBatchOfProxies ~ allProxyScores:", allProxyScores)
        const isSelfGenerated = proxyScoreMetadata.selfGenerated === true;

        // Sanity check in case the proxy metadata is not being returned
        const noPropertyReturned = typeof proxyScoreMetadata?.fraud_score === "number";

        if (noPropertyReturned && sanityBatchOfProxiesSaved === false) {
            fs.writeFileSync(`${SELECTED_PROXY_PROVIDER_TO_ANALYZE}_${ANALYZER_API_NAME}_${dateString}_SANITH_CHECK.json`, JSON.stringify(allProxyScores));
            sanityBatchOfProxiesSaved = true;
        }
        
        if (isProxy === true) {
            console.log("🚀 ~ file: ipqs.js:305 ~ scoreBatchOfProxies ~ isProxy:", isProxy)
            // We increment for all the proxies, but only incrmenet the real 
            // count when we have thereal proxies we are interested in
            counfOfProxiesDetectWithFakeBuffer++;
            overallProxyScoreAverageWithFakeBuffer = counfOfProxiesDetectWithFakeBuffer / countOfProxiesAnalyzed;
    
            if (isSelfGenerated === false) {
                console.log("🚀 ~ file: ipqs.js:315 ~ scoreBatchOfProxies ~ isSelfGenerated for proxy:", isSelfGenerated, "for proxy", proxyScoreMetadata);
                realCountOfProxiesDetected++;
            }
            
            realOverallProxyScoreAverage += realCountOfProxiesDetected / countOfProxiesAnalyzed;
        }

        if (i > 190 && firstBatchOfProxiesSaved === false) {
            fs.writeFileSync(`${SELECTED_PROXY_PROVIDER_TO_ANALYZE}_${ANALYZER_API_NAME}_${dateString}_AFTER_MAX_COUNT.json`, JSON.stringify(allProxyScores));
            
            firstBatchOfProxiesSaved = true;
        }
        
    }

    fs.writeFileSync(`${SELECTED_PROXY_PROVIDER_TO_ANALYZE}_${ANALYZER_API_NAME}_${dateString}_FINAL.json`, JSON.stringify(allProxyScores));

    console.log("@scoreBatchOfProxies: countOfProxiesAnalyzed: ", countOfProxiesAnalyzed);
    console.log("@scoreBatchOfProxies: counfOfProxiesDetectWithFakeBuffer: ", counfOfProxiesDetectWithFakeBuffer);
    console.log("@scoreBatchOfProxies: realCountOfProxiesDetected: ", realCountOfProxiesDetected);
    console.log("@scoreBatchOfProxies: overallProxyScoreAverageWithFakeBuffer: ", overallProxyScoreAverageWithFakeBuffer);
    console.log("@scoreBatchOfProxies: realOverallProxyScoreAverage: ", realOverallProxyScoreAverage);
    console.log("@scoreBatchOfProxies: allProxyScores: ", allProxyScores);
    
    return {
        countOfProxiesAnalyzed,
        counfOfProxiesDetectWithFakeBuffer,
        realCountOfProxiesDetected,
        overallProxyScoreAverageWithFakeBuffer,
        realOverallProxyScoreAverage,
        allProxyScores, 
    }
    
}

async function analyzeProxyMetadataScore(proxyMetadata) {
    const ip = proxyMetadata.ip;
    console.log("🚀 ~ file: ipqs.js:329 ~ analyzeProxyMetadataScore ~ ABOUT TO ANALYZE NEW IP :", ip);
    
    const response = await checkUserIPAgainstIPQS(ip);
    console.log("🚀 ~ file: ipqs.js:329 ~ analyzeProxyMetadataScore ~ response:", response)
    const ipqsScoreMetadata = extractsNecessaryDataFromIPQSResponse(response);
    console.log("🚀 ~ file: ipqs.js:341 ~ analyzeProxyMetadataScore ~ ipqsScoreMetadata:", ipqsScoreMetadata)
    const mergedProxyScoreMetadata = Object.assign({}, proxyMetadata, ipqsScoreMetadata);
    return mergedProxyScoreMetadata;
}


async function analyzeProxyMetadataScoreAgainstAlienVault(proxyMetadata, sectionToCheck) {
    const ip = proxyMetadata.ip;
    const response = await checkUserIPAgainstAlientVault(ip, sectionToCheck);
    console.log("🚀 ~ file: ipqs.js:329 ~ analyzeProxyMetadataScoreAgainstAlienVault ~ response:", response)
    return response;
}

async function analyzeProxyMetadataScoreAgainstIPRegistry(proxyMetadata,) {
    const ip = proxyMetadata.ip;
    const response = await checkUserIPAgainstIPRegistryAPI(ip,);
    console.log("🚀 ~ file: ipqs.js:329 ~ analyzeProxyMetadataScoreAgainstIPRegistry ~ response:", response)
    return response;
}


function extractIPFromLine(line) {
    const match = line.match(/^([\d.]+):4444/);
    return match ? match[1] : null;
}

function extractIpAddress(string) {
    const ipPattern = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
    const match = string.match(ipPattern);
    return match ? match[0] : null;
}


function returnProxies() {
    const filePath = 'LATESTPROXIES_March8.txt';
    // const filePath = 'test.txt';
    const ipData = parseIPFile(filePath);
    console.log(ipData);
    return ipData;
}


function parseIPFile(filePath) {
    
    try {
        // Read the file synchronously
        const fileContent = fs.readFileSync(filePath, 'utf8');
        console.log("🚀 ~ parseIPFile ~ fileContent:", fileContent)

        // Split the file content into lines
        const lines = fileContent.split('\n');
        console.log("🚀 ~ parseIPFile ~ lines:", lines)

        // Initialize an array to store IP objects
        const ipArray = [];

        // Iterate through the lines and extract IP addresses
        for (const line of lines) {
            const ipAddress = extractIPFromLine(line);
            console.log("🚀 ~ parseIPFile ~ ipAddress:", ipAddress)
            const ipAddressStr = extractIpAddress(line);
            console.log("🚀 ~ parseIPFile ~ ipAddressStr:", ipAddressStr)
            // if (ipAddress) {
            //     ipArray.push({ ip: ipAddress });
            // }
            if (ipAddressStr) {
                ipArray.push({ ip: ipAddressStr });
            }
        }

        console.log("IP ARRAY: ipArray, ", ipArray);
        return ipArray;
    } catch (error) {
        console.error('Error reading or parsing the file:', error);
        return [];
    }
}


async function ipAnalyzer() {

    // 1.  Get the IP addresses that we are interested in
    const proxyProviderIPs = returnProxies();
    console.log("🚀 ~ file: ipqs.js:295 ~ ipAnalyzer ~ proxyProviderIPs:", proxyProviderIPs)
    // return true;
    
    const proxyProviderListLength = proxyProviderIPs.length;
    console.log("🚀 ~ file: ipqs.js:295 ~ ipAnalyzer ~ proxyProviderListLength:", proxyProviderListLength)

    const allIPs = [...proxyProviderIPs, ];
    console.log("🚀 ~ file: ~ ipAnalyzer ~ allIPs:", allIPs)

    // 5. Score proxies and save internally
    const batchOfProxiesScored = await scoreBatchOfProxies(allIPs);
    console.log("🚀 ~ file: ipAnalyzer ~ batchOfProxiesScored:", batchOfProxiesScored)
    

}


/**
 * Run program
 */

ipAnalyzer();
