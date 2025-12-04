/**
 * Mysa Integration App with MQTT Support
 * Version: 2.3.0
 * Author: Craig Dewar
 *
 * Handles:
 *  - AWS Cognito SRP authentication
 *  - AWS Cognito Identity credentials for MQTT
 *  - SigV4 presigned WebSocket URL for AWS IoT
 *  - Device discovery and child device creation
 *  - Real-time MQTT updates via WebSocket
 */

import groovy.transform.Field
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.math.BigInteger
import java.net.URLEncoder

@Field static final String APP_VERSION = "2.3.0"

// 3072-bit SRP group (RFC 3526 - group 15)
@Field static final BigInteger SRP_N = new BigInteger((
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
  "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
  "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
  "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
  "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
  "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
  "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
  "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
), 16)
@Field static final BigInteger SRP_g = BigInteger.valueOf(2)
@Field static final String MYSA_API_BASE = "https://app-prod.mysa.cloud"

// AWS IoT MQTT endpoint for Mysa
@Field static final String MQTT_ENDPOINT = "a3q27gia9qg3zy-ats.iot.us-east-1.amazonaws.com"
@Field static final String IDENTITY_POOL_ID = "us-east-1:ebd95d52-9995-45da-b059-56b865a18379"

definition(
    name: "Mysa Integration MQTT",
    namespace: "craigde",
    author: "Craig Dewar",
    description: "Integrates Mysa smart thermostats with Hubitat (with MQTT control)",
    category: "Green Living",
    iconUrl: "",
    iconX2Url: "",
    singleInstance: true
)

preferences {
    page(name: "mainPage")
    page(name: "credentialsPage")
    page(name: "devicesPage")
    page(name: "mqttPage")
}

def mainPage() {
    dynamicPage(name: "mainPage", title: "Mysa Integration", install: true, uninstall: true) {
        section {
            paragraph "Mysa Integration v${APP_VERSION}"
            href "credentialsPage", title: "Configure Credentials", description: "Set up your Mysa account"
            href "devicesPage", title: "Manage Devices", description: "Discover and manage thermostats"
            href "mqttPage", title: "MQTT Settings", description: "Configure real-time updates"
        }
        section("Settings") {
            input name: "pollInterval", type: "enum", title: "Poll Interval (backup)", 
                  options: ["1": "1 minute", "5": "5 minutes", "10": "10 minutes", "15": "15 minutes", "30": "30 minutes"], 
                  defaultValue: "15", required: true
            input name: "useMqtt", type: "bool", title: "Enable MQTT for real-time updates", defaultValue: true
            input name: "debugLogging", type: "bool", title: "Enable Debug Logging", defaultValue: false
        }
        if (state.idToken) {
            section("Status") {
                paragraph "✓ Authenticated"
                paragraph "Devices: ${getChildDevices()?.size() ?: 0}"
                paragraph "Last poll: ${state.lastPoll ?: 'Never'}"
                if (state.mqttConnected) {
                    paragraph "✓ MQTT Connected"
                } else if (useMqtt) {
                    paragraph "○ MQTT Not Connected"
                }
            }
        }
    }
}

def credentialsPage() {
    dynamicPage(name: "credentialsPage", title: "Mysa Credentials") {
        section {
            input name: "region", type: "text", title: "AWS Region", required: true, defaultValue: "us-east-1"
            input name: "cognitoUserPoolId", type: "text", title: "Cognito User Pool ID", required: true, defaultValue: "us-east-1_GUFWfhI7g"
            input name: "cognitoClientId", type: "text", title: "Cognito App Client ID", required: true, defaultValue: "19efs8tgqe942atbqmot5m36t3"
            input name: "username", type: "text", title: "Email", required: true
            input name: "password", type: "password", title: "Password", required: true
        }
        section {
            input name: "testAuth", type: "button", title: "Test Authentication"
        }
        if (state.authStatus) {
            section {
                paragraph state.authStatus
            }
        }
    }
}

def devicesPage() {
    dynamicPage(name: "devicesPage", title: "Mysa Devices") {
        if (!state.idToken) {
            section {
                paragraph "Please configure and test credentials first."
            }
        } else {
            section {
                input name: "discoverDevices", type: "button", title: "Discover Devices"
            }
            if (state.discoveredDevices) {
                section("Discovered Devices") {
                    state.discoveredDevices.each { id, dev ->
                        def child = getChildDevice("mysa2-${id}")
                        def status = child ? "✓ Created" : "Not created"
                        paragraph "${dev.Name} (${dev.Model}) - ${status}"
                    }
                }
                section {
                    input name: "createDevices", type: "button", title: "Create All Devices"
                }
            }
        }
    }
}

def mqttPage() {
    dynamicPage(name: "mqttPage", title: "MQTT Configuration") {
        section {
            paragraph "MQTT provides real-time updates from your Mysa thermostats."
            paragraph "MQTT Endpoint: ${MQTT_ENDPOINT}"
            paragraph "Identity Pool: ${IDENTITY_POOL_ID}"
        }
        if (state.idToken) {
            section {
                input name: "testMqtt", type: "button", title: "Test MQTT Credentials"
            }
            if (state.mqttStatus) {
                section("MQTT Status") {
                    paragraph state.mqttStatus
                }
            }
        } else {
            section {
                paragraph "Please authenticate first to test MQTT."
            }
        }
    }
}

def appButtonHandler(btn) {
    switch(btn) {
        case "testAuth":
            testAuthentication()
            break
        case "discoverDevices":
            discoverDevices()
            break
        case "createDevices":
            createAllDevices()
            break
        case "testMqtt":
            testMqttCredentials()
            break
    }
}

def installed() {
    logInfo "Mysa Integration installed"
    initialize()
}

def updated() {
    logInfo "Mysa Integration updated"
    unschedule()
    initialize()
}

def uninstalled() {
    logInfo "Mysa Integration uninstalled"
    getChildDevices().each { deleteChildDevice(it.deviceNetworkId) }
}

def initialize() {
    if (state.idToken && state.refreshToken) {
        schedulePoll()
        runIn(5, "poll")  // Initial poll after 5 seconds
    }
}

def schedulePoll() {
    def interval = (pollInterval ?: "15").toInteger()
    switch(interval) {
        case 1:
            runEvery1Minute("poll")
            break
        case 5:
            runEvery5Minutes("poll")
            break
        case 10:
            runEvery10Minutes("poll")
            break
        case 15:
            runEvery15Minutes("poll")
            break
        case 30:
            runEvery30Minutes("poll")
            break
        default:
            runEvery15Minutes("poll")
    }
    logDebug "Scheduled polling every ${interval} minute(s)"
}

/* =========================
 * Authentication
 * ========================= */

def testAuthentication() {
    logInfo "Testing authentication..."
    
    // Validate inputs are present
    if (!region || !cognitoUserPoolId || !cognitoClientId || !username || !password) {
        state.authStatus = "✗ Please fill in all credential fields and click Done first, then test again."
        logWarn "Missing required credentials"
        return
    }
    
    try {
        def tokens = srpLogin(region, cognitoUserPoolId, cognitoClientId, username, password)
        state.idToken = tokens.idToken
        state.accessToken = tokens.accessToken
        state.refreshToken = tokens.refreshToken
        state.tokenExpiry = now() + ((tokens.expiresInSec ?: 3600) * 1000)
        state.authStatus = "✓ Authentication successful!"
        logInfo "Authentication successful"
    } catch (e) {
        state.authStatus = "✗ Authentication failed: ${e.message}"
        logWarn "Authentication failed: ${e}"
    }
}

def ensureAuthenticated() {
    // Check if token is expired or will expire soon (within 5 minutes)
    if (!state.idToken || !state.tokenExpiry || (state.tokenExpiry - now()) < 300000) {
        logDebug "Token expired or missing, re-authenticating..."
        try {
            def tokens = srpLogin(region, cognitoUserPoolId, cognitoClientId, username, password)
            state.idToken = tokens.idToken
            state.accessToken = tokens.accessToken
            state.refreshToken = tokens.refreshToken
            state.tokenExpiry = now() + ((tokens.expiresInSec ?: 3600) * 1000)
            return true
        } catch (e) {
            logWarn "Re-authentication failed: ${e}"
            return false
        }
    }
    return true
}

/* =========================
 * AWS Cognito Identity (for MQTT)
 * ========================= */

def testMqttCredentials() {
    logInfo "Testing MQTT credentials..."
    try {
        def awsCreds = getAwsCredentials()
        if (awsCreds.accessKeyId) {
            state.mqttStatus = """✓ AWS Credentials obtained:
AccessKeyId: ${awsCreds.accessKeyId?.take(10)}...
IdentityId: ${awsCreds.identityId}
Expiration: ${awsCreds.expiration}"""
            
            // Try generating a presigned URL
            def presignedUrl = generateMqttPresignedUrl(awsCreds)
            state.mqttStatus += "\n\n✓ Presigned URL generated (${presignedUrl?.length()} chars)"
            
            logInfo "MQTT credentials test successful"
        } else {
            state.mqttStatus = "✗ Failed to get AWS credentials"
        }
    } catch (e) {
        state.mqttStatus = "✗ MQTT credential test failed: ${e.message}"
        logWarn "MQTT credential test failed: ${e}"
    }
}

def getAwsCredentials() {
    if (!state.idToken) {
        throw new Exception("Not authenticated - no idToken")
    }
    
    // Parse the idToken to get the issuer
    def tokenParts = state.idToken.split("\\.")
    def payloadJson = new String(tokenParts[1].decodeBase64())
    def payload = new groovy.json.JsonSlurper().parseText(payloadJson)
    def issuer = payload.iss?.replace("https://", "")
    
    if (!issuer) {
        throw new Exception("Could not extract issuer from idToken")
    }
    
    logDebug "Token issuer: ${issuer}"
    
    // Step 1: GetId - get the Cognito Identity ID
    def getIdResult = cognitoIdentityRequest("GetId", [
        IdentityPoolId: IDENTITY_POOL_ID,
        Logins: [(issuer): state.idToken]
    ])
    
    def identityId = getIdResult?.IdentityId
    if (!identityId) {
        throw new Exception("Failed to get IdentityId: ${getIdResult}")
    }
    
    logDebug "Got IdentityId: ${identityId}"
    
    // Step 2: GetCredentialsForIdentity - get temporary AWS credentials
    def credsResult = cognitoIdentityRequest("GetCredentialsForIdentity", [
        IdentityId: identityId,
        Logins: [(issuer): state.idToken]
    ])
    
    def creds = credsResult?.Credentials
    if (!creds?.AccessKeyId) {
        throw new Exception("Failed to get credentials: ${credsResult}")
    }
    
    return [
        identityId: identityId,
        accessKeyId: creds.AccessKeyId,
        secretKey: creds.SecretKey,
        sessionToken: creds.SessionToken,
        expiration: creds.Expiration
    ]
}

private Map cognitoIdentityRequest(String action, Map body) {
    def result = null
    def endpoint = "https://cognito-identity.${region}.amazonaws.com/"
    
    try {
        httpPost([
            uri: endpoint,
            headers: [
                "X-Amz-Target": "AWSCognitoIdentityService.${action}",
                "Content-Type": "application/x-amz-json-1.1"
            ],
            requestContentType: "application/json",
            contentType: "application/json",
            body: groovy.json.JsonOutput.toJson(body),
            timeout: 30
        ]) { resp ->
            if (resp?.data) {
                result = resp.data
                logDebug "CognitoIdentity ${action} response: ${result}"
            }
        }
    } catch (e) {
        logWarn "CognitoIdentity ${action} failed: ${e.message}"
        throw e
    }
    
    return result
}

/* =========================
 * AWS SigV4 URL Signing for MQTT WebSocket
 * ========================= */

def generateMqttPresignedUrl(Map awsCreds) {
    def method = "GET"
    def service = "iotdevicegateway"
    def host = MQTT_ENDPOINT
    def regionName = region
    def canonicalUri = "/mqtt"
    
    // Current time
    def now = new Date()
    def dateStamp = now.format("yyyyMMdd", TimeZone.getTimeZone("UTC"))
    def amzDate = now.format("yyyyMMdd'T'HHmmss'Z'", TimeZone.getTimeZone("UTC"))
    
    // Credential scope
    def credentialScope = "${dateStamp}/${regionName}/${service}/aws4_request"
    
    // Build canonical query string (alphabetically sorted)
    def queryParams = [
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": URLEncoder.encode("${awsCreds.accessKeyId}/${credentialScope}", "UTF-8"),
        "X-Amz-Date": amzDate,
        "X-Amz-SignedHeaders": "host"
    ]
    
    // Sort and build query string
    def canonicalQueryString = queryParams.sort { it.key }.collect { k, v -> "${k}=${v}" }.join("&")
    
    // Canonical headers
    def canonicalHeaders = "host:${host}\n"
    def signedHeaders = "host"
    
    // Payload hash (empty for presigned URLs)
    def payloadHash = sha256Hash("")
    
    // Create canonical request
    def canonicalRequest = [
        method,
        canonicalUri,
        canonicalQueryString,
        canonicalHeaders,
        signedHeaders,
        payloadHash
    ].join("\n")
    
    logDebug "Canonical request:\n${canonicalRequest}"
    
    // Create string to sign
    def algorithm = "AWS4-HMAC-SHA256"
    def hashedCanonicalRequest = sha256Hash(canonicalRequest)
    def stringToSign = [
        algorithm,
        amzDate,
        credentialScope,
        hashedCanonicalRequest
    ].join("\n")
    
    logDebug "String to sign:\n${stringToSign}"
    
    // Calculate signing key
    def signingKey = getSignatureKey(awsCreds.secretKey, dateStamp, regionName, service)
    
    // Calculate signature
    def signature = bytesToHex(hmacSha256(signingKey, stringToSign))
    
    logDebug "Signature: ${signature}"
    
    // Build the presigned URL
    // IMPORTANT: For Mysa/AWS IoT, the session token goes AFTER the signature
    def presignedUrl = "wss://${host}${canonicalUri}?${canonicalQueryString}&X-Amz-Signature=${signature}&X-Amz-Security-Token=${URLEncoder.encode(awsCreds.sessionToken, "UTF-8")}"
    
    return presignedUrl
}

private byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName) {
    byte[] kSecret = ("AWS4" + key).getBytes("UTF-8")
    byte[] kDate = hmacSha256(kSecret, dateStamp)
    byte[] kRegion = hmacSha256(kDate, regionName)
    byte[] kService = hmacSha256(kRegion, serviceName)
    byte[] kSigning = hmacSha256(kService, "aws4_request")
    return kSigning
}

private String sha256Hash(String data) {
    MessageDigest digest = MessageDigest.getInstance("SHA-256")
    byte[] hash = digest.digest(data.getBytes("UTF-8"))
    return bytesToHex(hash)
}

private byte[] hmacSha256(byte[] key, String data) {
    Mac mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(data.getBytes("UTF-8"))
}

/* =========================
 * MQTT Details for Child Drivers
 * ========================= */

def getMqttConnectionDetails() {
    if (!ensureAuthenticated()) {
        return [success: false, error: "Not authenticated"]
    }
    
    try {
        def awsCreds = getAwsCredentials()
        def presignedUrl = generateMqttPresignedUrl(awsCreds)
        
        // Get user info for subscription topics
        def userInfo = getUserInfo()
        def userId = userInfo?.Id ?: awsCreds.identityId
        
        // The username (email) is needed for src.ref in MQTT commands
        // Per bourquep's SDK: src.ref should be the username (email), not the UUID
        def userEmail = username  // from preferences - this is the login email
        
        // Get all device IDs from child devices
        def deviceIds = getChildDevices()?.collect { it.getDataValue("mysaId") }?.findAll { it } ?: []
        
        // If no child devices yet, try from discovered devices
        if (deviceIds.isEmpty() && state.discoveredDevices) {
            deviceIds = state.discoveredDevices.keySet().toList()
        }
        
        if (deviceIds.isEmpty()) {
            logWarn "No devices found for MQTT subscription"
        }
        
        // Correct topics based on dlenski's research:
        // Subscribe: /v1/dev/{deviceId}/out (messages FROM thermostat)
        // Publish: /v1/dev/{deviceId}/in (messages TO thermostat)
        def subscribeTopics = deviceIds.collect { deviceId -> "/v1/dev/${deviceId}/out" }
        
        logDebug "MQTT subscribe topics: ${subscribeTopics}"
        
        return [
            success: true,
            presignedUrl: presignedUrl,
            userId: userId,
            userEmail: userEmail,  // Email for src.ref in MQTT commands
            identityId: awsCreds.identityId,
            // Subscription topics - one per device
            subscribeTopics: subscribeTopics,
            // Publish base (append deviceId/in)
            publishTopicBase: "/v1/dev",
            expiresAt: awsCreds.expiration
        ]
    } catch (e) {
        logWarn "Failed to get MQTT connection details: ${e}"
        return [success: false, error: e.message]
    }
}

def getUserInfo() {
    if (!ensureAuthenticated()) return null
    
    try {
        def result = null
        httpGet([
            uri: "${MYSA_API_BASE}/users",
            headers: [ Authorization: state.idToken ],
            timeout: 30
        ]) { resp ->
            result = resp?.data?.UserObj
        }
        return result
    } catch (e) {
        logWarn "Failed to get user info: ${e}"
        return null
    }
}

/* =========================
 * Device Discovery & Creation
 * ========================= */

def discoverDevices() {
    logInfo "Discovering devices..."
    if (!ensureAuthenticated()) {
        logWarn "Not authenticated"
        return
    }
    
    try {
        httpGet([
            uri: "${MYSA_API_BASE}/devices",
            headers: [ Authorization: state.idToken ],
            timeout: 30
        ]) { resp ->
            if (resp?.data?.DevicesObj) {
                state.discoveredDevices = resp.data.DevicesObj
                logInfo "Discovered ${state.discoveredDevices.size()} device(s)"
            }
        }
    } catch (e) {
        logWarn "Device discovery failed: ${e}"
    }
}

def createAllDevices() {
    if (!state.discoveredDevices) {
        logWarn "No devices discovered"
        return
    }
    
    def firstDevice = true
    state.discoveredDevices.each { id, dev ->
        def child = createChildDevice(id, dev)
        // First device becomes the MQTT master (always, since this is the MQTT app)
        if (child && firstDevice) {
            logInfo "Setting ${child.label} as MQTT master"
            child.updateDataValue("mqttMaster", "true")
            // Trigger initialize to start MQTT connection
            child.initialize()
            firstDevice = false
        }
    }
    
    // Do initial poll to populate data
    runIn(2, "poll")
}

def createChildDevice(String deviceId, Map deviceInfo) {
    def dni = "mysa2-${deviceId}"  // Use mysa2- prefix to avoid collision with v1
    def existing = getChildDevice(dni)
    
    if (existing) {
        logDebug "Device ${dni} already exists"
        return existing
    }
    
    logInfo "Creating child device: ${deviceInfo.Name} (${deviceId})"
    
    try {
        def child = addChildDevice(
            "craigde",                         // namespace
            "Mysa Thermostat MQTT",           // driver name (new driver with MQTT)
            dni,                               // device network ID
            [
                name: "Mysa MQTT ${deviceInfo.Name}",
                label: "${deviceInfo.Name} (MQTT)",
                isComponent: false
            ]
        )
        
        // Set device-specific data
        child.updateDataValue("mysaId", deviceId)
        child.updateDataValue("model", deviceInfo.Model ?: "Unknown")
        child.updateDataValue("voltage", deviceInfo.Voltage?.toString() ?: "240")
        child.updateDataValue("format", deviceInfo.Format ?: "celsius")
        child.updateDataValue("mqttMaster", "false")
        
        // Set model as attribute for visibility in UI
        child.sendEvent(name: "model", value: deviceInfo.Model ?: "Unknown")
        
        return child
    } catch (e) {
        logWarn "Failed to create child device: ${e}"
        return null
    }
}

/* =========================
 * MQTT Message Handling (called by child driver)
 * ========================= */

def processMqttMessage(childDev, String topic, Map payload) {
    logDebug "Processing MQTT message from topic ${topic}: ${payload}"
    
    // Extract device ID from topic: /v1/dev/{deviceId}/out
    def matcher = (topic =~ /\/v1\/dev\/([^\/]+)\/out/)
    if (!matcher.find()) {
        logDebug "Cannot extract device ID from topic: ${topic}"
        return
    }
    
    def deviceId = matcher.group(1)
    def targetDevice = getChildDevice("mysa2-${deviceId}")
    if (!targetDevice) {
        logDebug "No child device found for ${deviceId}"
        return
    }
    
    // Handle different Mysa message types based on dlenski's research
    // MsgType 0: Stream data (temperature, humidity, setpoint)
    // MsgType 1: Setpoint change notification
    // MsgType 4: Device info/log
    // msg 44: Command response (body.state contains current state)
    
    def msgType = payload.MsgType
    def msg = payload.msg
    
    if (msgType == 0) {
        // Stream data - realtime updates
        updateChildFromStream(targetDevice, payload)
    } else if (msgType == 1) {
        // Setpoint changed notification
        if (payload.Next != null) {
            updateChildSetpoint(targetDevice, payload.Next)
        }
    } else if (msg == 44 && payload.body?.state) {
        // Command response with current state
        updateChildFromState(targetDevice, payload.body.state)
    } else if (payload.body?.ambTemp != null || payload.body?.stpt != null) {
        // Body-style status update
        updateChildFromBody(targetDevice, payload.body)
    }
}

def updateChildFromStream(child, Map payload) {
    def format = child.getDataValue("format") ?: "celsius"
    def useFahrenheit = (format == "fahrenheit")
    
    child.sendEvent(name: "lastUpdate", value: new Date().format("yyyy-MM-dd HH:mm:ss"))
    
    // ComboTemp or MainTemp = actual temperature
    def tempC = payload.MainTemp ?: payload.ComboTemp
    if (tempC != null) {
        def temp = useFahrenheit ? celsiusToFahrenheit(tempC) : tempC
        child.sendEvent(name: "temperature", value: Math.round(temp), unit: useFahrenheit ? "°F" : "°C")
    }
    
    // SetPoint
    if (payload.SetPoint != null) {
        def setpointC = payload.SetPoint
        def setpoint = useFahrenheit ? celsiusToFahrenheit(setpointC) : setpointC
        child.sendEvent(name: "heatingSetpoint", value: Math.round(setpoint), unit: useFahrenheit ? "°F" : "°C")
        child.sendEvent(name: "thermostatSetpoint", value: Math.round(setpoint), unit: useFahrenheit ? "°F" : "°C")
    }
    
    // Humidity
    if (payload.Humidity != null) {
        child.sendEvent(name: "humidity", value: payload.Humidity.toInteger(), unit: "%")
    }
    
    // Current (power in amps - V1 devices have current sensor)
    if (payload.Current != null) {
        // Estimate power: P = I * V (assume 240V for baseboard heaters)
        def voltage = 240  // Most baseboard heaters are 240V
        def power = round(payload.Current * voltage, 0)
        child.sendEvent(name: "power", value: power, unit: "W")
    }
    
    logDebug "Updated ${child.label} from stream: temp=${tempC}, setpoint=${payload.SetPoint}, humidity=${payload.Humidity}"
}

def updateChildFromBody(child, Map body) {
    def format = child.getDataValue("format") ?: "celsius"
    def useFahrenheit = (format == "fahrenheit")
    
    child.sendEvent(name: "lastUpdate", value: new Date().format("yyyy-MM-dd HH:mm:ss"))
    
    // ambTemp = ambient/actual temperature
    if (body.ambTemp != null) {
        def tempC = body.ambTemp
        def temp = useFahrenheit ? celsiusToFahrenheit(tempC) : tempC
        child.sendEvent(name: "temperature", value: Math.round(temp), unit: useFahrenheit ? "°F" : "°C")
    }
    
    // stpt = setpoint
    if (body.stpt != null) {
        def setpointC = body.stpt
        def setpoint = useFahrenheit ? celsiusToFahrenheit(setpointC) : setpointC
        child.sendEvent(name: "heatingSetpoint", value: Math.round(setpoint), unit: useFahrenheit ? "°F" : "°C")
        child.sendEvent(name: "thermostatSetpoint", value: Math.round(setpoint), unit: useFahrenheit ? "°F" : "°C")
    }
    
    // hum = humidity
    if (body.hum != null) {
        child.sendEvent(name: "humidity", value: body.hum.toInteger(), unit: "%")
    }
    
    // dtyCycle = duty cycle (1.0 = heating, 0.0 = idle)
    if (body.dtyCycle != null) {
        def opState = (body.dtyCycle > 0) ? "heating" : "idle"
        child.sendEvent(name: "thermostatOperatingState", value: opState)
        child.sendEvent(name: "dutyCycle", value: round(body.dtyCycle, 2))
    }
    
    logDebug "Updated ${child.label} from body: ambTemp=${body.ambTemp}, stpt=${body.stpt}"
}

def updateChildFromState(child, Map stateData) {
    def format = child.getDataValue("format") ?: "celsius"
    def useFahrenheit = (format == "fahrenheit")
    
    child.sendEvent(name: "lastUpdate", value: new Date().format("yyyy-MM-dd HH:mm:ss"))
    
    // sp = setpoint
    if (stateData.sp != null) {
        def setpointC = stateData.sp
        def setpoint = useFahrenheit ? celsiusToFahrenheit(setpointC) : setpointC
        child.sendEvent(name: "heatingSetpoint", value: Math.round(setpoint), unit: useFahrenheit ? "°F" : "°C")
        child.sendEvent(name: "thermostatSetpoint", value: Math.round(setpoint), unit: useFahrenheit ? "°F" : "°C")
    }
    
    // md = mode (1 = off, 3 = heat)
    if (stateData.md != null) {
        def mode = (stateData.md == 3) ? "heat" : "off"
        child.sendEvent(name: "thermostatMode", value: mode)
    }
    
    logDebug "Updated ${child.label} from state: sp=${stateData.sp}, md=${stateData.md}"
}

def updateChildSetpoint(child, BigDecimal setpointC) {
    def format = child.getDataValue("format") ?: "celsius"
    def useFahrenheit = (format == "fahrenheit")
    def setpoint = useFahrenheit ? celsiusToFahrenheit(setpointC) : setpointC
    
    child.sendEvent(name: "lastUpdate", value: new Date().format("yyyy-MM-dd HH:mm:ss"))
    child.sendEvent(name: "heatingSetpoint", value: Math.round(setpoint), unit: useFahrenheit ? "°F" : "°C")
    child.sendEvent(name: "thermostatSetpoint", value: Math.round(setpoint), unit: useFahrenheit ? "°F" : "°C")
    
    logDebug "Updated ${child.label} setpoint to ${setpoint}"
}

/* =========================
 * Polling & Updates (REST API fallback)
 * ========================= */

def poll() {
    logDebug "Polling for updates..."
    
    if (!ensureAuthenticated()) {
        logWarn "Cannot poll - not authenticated"
        return
    }
    
    try {
        httpGet([
            uri: "${MYSA_API_BASE}/devices/state",
            headers: [ Authorization: state.idToken ],
            timeout: 30
        ]) { resp ->
            if (resp?.data?.DeviceStatesObj) {
                state.lastPoll = new Date().format("yyyy-MM-dd HH:mm:ss")
                processDeviceStates(resp.data.DeviceStatesObj)
            }
        }
    } catch (e) {
        logWarn "Poll failed: ${e}"
        // If we get a 401, try to re-authenticate
        if (e.message?.contains("401") || e.message?.contains("Unauthorized")) {
            state.idToken = null
            state.tokenExpiry = 0
        }
    }
}

def processDeviceStates(Map states) {
    states.each { deviceId, stateData ->
        def child = getChildDevice("mysa2-${deviceId}")
        if (child) {
            updateChildDevice(child, stateData)
        }
    }
}

def updateChildDevice(child, Map stateData) {
    def format = child.getDataValue("format") ?: "celsius"
    def useFahrenheit = (format == "fahrenheit")
    
    child.sendEvent(name: "lastUpdate", value: new Date().format("yyyy-MM-dd HH:mm:ss"))
    
    if (stateData.CorrectedTemp?.v != null) {
        def tempC = stateData.CorrectedTemp.v
        def temp = useFahrenheit ? celsiusToFahrenheit(tempC) : tempC
        child.sendEvent(name: "temperature", value: Math.round(temp), unit: useFahrenheit ? "°F" : "°C")
    }
    
    if (stateData.SetPoint?.v != null) {
        def setpointC = stateData.SetPoint.v
        def setpoint = useFahrenheit ? celsiusToFahrenheit(setpointC) : setpointC
        child.sendEvent(name: "heatingSetpoint", value: Math.round(setpoint), unit: useFahrenheit ? "°F" : "°C")
        child.sendEvent(name: "thermostatSetpoint", value: Math.round(setpoint), unit: useFahrenheit ? "°F" : "°C")
    }
    
    if (stateData.Humidity?.v != null) {
        child.sendEvent(name: "humidity", value: stateData.Humidity.v.toInteger(), unit: "%")
    }
    
    if (stateData.TstatMode?.v != null) {
        def mode = stateData.TstatMode.v
        def modeStr = (mode == 3) ? "heat" : "off"
        child.sendEvent(name: "thermostatMode", value: modeStr)
    }
    
    if (stateData.Duty?.v != null) {
        def duty = stateData.Duty.v
        def opState = (duty > 0) ? "heating" : "idle"
        child.sendEvent(name: "thermostatOperatingState", value: opState)
    }
    
    if (stateData.Connected?.v != null) {
        child.sendEvent(name: "presence", value: stateData.Connected.v ? "present" : "not present")
    }
    
    if (stateData.Rssi?.v != null) {
        child.sendEvent(name: "rssi", value: stateData.Rssi.v)
    }
}

def celsiusToFahrenheit(c) {
    return (c * 9/5) + 32
}

def round(value, precision) {
    return Math.round(value * Math.pow(10, precision)) / Math.pow(10, precision)
}

/* =========================
 * Child Device Commands
 * ========================= */

def childRefresh(String dni) {
    logDebug "Child refresh requested: ${dni}"
    poll()
}

def childSetHeatingSetpoint(String dni, temperature) {
    logDebug "childSetHeatingSetpoint: ${dni} -> ${temperature}"
    
    def child = getChildDevice(dni)
    def deviceId = child?.getDataValue("mysaId")
    if (!deviceId) {
        logWarn "No device ID found for ${dni}"
        return
    }
    
    // Convert to Celsius if needed
    def format = child.getDataValue("format") ?: "celsius"
    def tempC = (format == "fahrenheit") ? ((temperature - 32) * 5/9) : temperature
    tempC = Math.round(tempC * 10) / 10  // Round to 1 decimal
    
    logInfo "Setting setpoint for ${deviceId} to ${tempC}°C"
    
    // REST API control doesn't work for Mysa - MQTT is required
    // The device state will update when we receive MQTT confirmation
    logWarn "REST API fallback called but Mysa requires MQTT for control. Ensure MQTT is connected."
}

def childSetThermostatMode(String dni, mode) {
    logDebug "childSetThermostatMode: ${dni} -> ${mode}"
    
    def child = getChildDevice(dni)
    def deviceId = child?.getDataValue("mysaId")
    if (!deviceId) {
        logWarn "No device ID found for ${dni}"
        return
    }
    
    logInfo "Setting mode for ${deviceId} to ${mode}"
    
    // REST API control doesn't work for Mysa - MQTT is required
    // The device state will update when we receive MQTT confirmation
    logWarn "REST API fallback called but Mysa requires MQTT for control. Ensure MQTT is connected."
}

// For MQTT control commands - to be implemented
def sendMqttCommand(String deviceId, Map command) {
    logDebug "sendMqttCommand: ${deviceId} -> ${command}"
    
    // Find the MQTT master device to send the command
    def masterDevice = getChildDevices().find { it.getDataValue("mqttMaster") == "true" }
    if (masterDevice) {
        // The master device will handle the actual MQTT publish
        masterDevice.publishMqttCommand(deviceId, command)
    } else {
        logWarn "No MQTT master device found, cannot send command"
    }
}

/* =========================
 * SRP Authentication
 * ========================= */

private Map srpLogin(String region, String userPoolId, String clientId, String user, String pass) {
    final String ep = "https://cognito-idp.${region}.amazonaws.com/"
    final String poolName = userPoolId.split("_",2)[1]

    BigInteger a = randomA()
    BigInteger A = SRP_g.modPow(a, SRP_N)
    String Ahex = getPaddedHex(A)

    // InitiateAuth
    Map initResp = awsJson(ep, "AWSCognitoIdentityProviderService.InitiateAuth", [
        AuthFlow: "USER_SRP_AUTH",
        ClientId: clientId,
        AuthParameters: [ USERNAME: user, SRP_A: Ahex ]
    ])

    if (!(initResp instanceof Map) || !initResp.ChallengeName) {
        throw new Exception("InitiateAuth failed: ${initResp}")
    }
    if (!"PASSWORD_VERIFIER".equals(initResp.ChallengeName)) {
        throw new Exception("Unexpected challenge: ${initResp.ChallengeName}")
    }

    def cp = initResp.ChallengeParameters ?: [:]
    String userIdForSrp = cp.USER_ID_FOR_SRP
    String srpBhex = cp.SRP_B
    String saltHex = cp.SALT
    String secretBlockB64 = cp.SECRET_BLOCK
    
    if (!userIdForSrp || !srpBhex || !saltHex || !secretBlockB64) {
        throw new Exception("Missing SRP challenge parameters")
    }

    BigInteger B = new BigInteger(srpBhex, 16)
    if (B.mod(SRP_N).equals(BigInteger.ZERO)) throw new Exception("Invalid B")

    String uInputHex = getPaddedHex(A) + getPaddedHex(B)
    String uHex = getHashFromHex(uInputHex)
    BigInteger u = new BigInteger(uHex, 16)
    if (u.equals(BigInteger.ZERO)) throw new Exception("u == 0")

    String kInputHex = getPaddedHex(SRP_N) + getPaddedHex(SRP_g)
    String kHex = getHashFromHex(kInputHex)
    BigInteger k = new BigInteger(kHex, 16)

    String passwordHashInput = poolName + userIdForSrp + ":" + pass
    String innerHashHex = getHashFromData(passwordHashInput.getBytes("UTF-8"))
    String xInputHex = getPaddedHex(new BigInteger(saltHex, 16)) + innerHashHex
    String xHex = getHashFromHex(xInputHex)
    BigInteger x = new BigInteger(xHex, 16)

    BigInteger gx = SRP_g.modPow(x, SRP_N)
    BigInteger kgx = k.multiply(gx).mod(SRP_N)
    BigInteger diff = B.subtract(kgx)
    if (diff.signum() < 0) diff = diff.add(SRP_N)
    BigInteger base = diff.mod(SRP_N)
    BigInteger exp = a.add(u.multiply(x))
    BigInteger S = base.modPow(exp, SRP_N)

    byte[] infoBytes = concatBytes("Caldera Derived Key".getBytes("UTF-8"), [(byte)1] as byte[])
    byte[] hkdfKey = hkdfAws(
        hexToBytes(getPaddedHex(S)),
        hexToBytes(getPaddedHex(u)),
        infoBytes
    )

    String timestamp = awsTimestamp()
    byte[] secretBlockBytes = secretBlockB64.decodeBase64()
    
    ByteArrayOutputStream msg = new ByteArrayOutputStream()
    msg.write(poolName.getBytes("UTF-8"))
    msg.write(userIdForSrp.getBytes("UTF-8"))
    msg.write(secretBlockBytes)
    msg.write(timestamp.getBytes("UTF-8"))
    
    String claimSigB64 = hmac(hkdfKey, msg.toByteArray()).encodeBase64().toString()

    Map resp = awsJson(ep, "AWSCognitoIdentityProviderService.RespondToAuthChallenge", [
        ChallengeName: "PASSWORD_VERIFIER",
        ClientId: clientId,
        ChallengeResponses: [
            PASSWORD_CLAIM_SECRET_BLOCK: secretBlockB64,
            PASSWORD_CLAIM_SIGNATURE: claimSigB64,
            TIMESTAMP: timestamp,
            USERNAME: userIdForSrp
        ]
    ])

    def ar = resp?.AuthenticationResult
    if (ar?.IdToken) {
        return [ 
            idToken: ar.IdToken, 
            accessToken: ar.AccessToken, 
            refreshToken: ar.RefreshToken, 
            expiresInSec: (ar.ExpiresIn ?: 3600) 
        ]
    }

    throw new Exception("Login failed: ${resp}")
}

/* =========================
 * HTTP Helper
 * ========================= */

private Map awsJson(String url, String target, Map body) {
    Map out = [status:-1, json:null, text:null, err:null]
    try {
        String jsonBody = groovy.json.JsonOutput.toJson(body)
        
        httpPost([
            uri: url,
            headers: [
                "X-Amz-Target": target,
                "Content-Type": "application/x-amz-json-1.1"
            ],
            requestContentType: "application/json",
            contentType: "application/json",
            body: jsonBody,
            timeout: 30
        ]) { resp ->
            out.status = (resp?.status ?: -1)
            if (resp?.data instanceof Map) {
                out.json = (Map) resp.data
                return
            }
            String raw = resp?.data?.toString()
            out.text = raw
            if (raw?.trim()?.startsWith("{")) {
                try { out.json = new groovy.json.JsonSlurper().parseText(raw.trim()) as Map } catch (ignored) {}
            }
        }
    } catch (e) {
        out.err = e?.toString()
        logWarn "AWS call error ${target}: ${e?.message}"
    }
    return (out.json != null) ? out.json : out
}

/* =========================
 * Crypto Helpers
 * ========================= */

private static String getPaddedHex(BigInteger bi) {
    if (bi.signum() < 0) {
        throw new Exception("Negative BigInteger not supported")
    }
    
    String hex = bi.toString(16)
    if (hex.length() % 2 == 1) {
        hex = "0" + hex
    }
    
    char first = hex.charAt(0)
    if ((first >= '8' && first <= '9') || 
        (first >= 'a' && first <= 'f') || 
        (first >= 'A' && first <= 'F')) {
        hex = "00" + hex
    }
    
    return hex
}

private static String getHashFromHex(String hexStr) {
    byte[] bytes = hexToBytes(hexStr)
    return getHashFromData(bytes)
}

private static String getHashFromData(byte[] data) {
    MessageDigest md = MessageDigest.getInstance("SHA-256")
    byte[] hash = md.digest(data)
    String hex = bytesToHex(hash)
    while (hex.length() < 64) {
        hex = "0" + hex
    }
    return hex
}

private static byte[] hkdfAws(byte[] ikm, byte[] salt, byte[] info) {
    byte[] prk = hmac(salt, ikm)
    byte[] okm = hmac(prk, info)
    byte[] result = new byte[16]
    for (int i = 0; i < 16; i++) {
        result[i] = okm[i]
    }
    return result
}

private BigInteger randomA() {
    byte[] r = new byte[128]
    new Random(now()).nextBytes(r)
    return new BigInteger(1, r)
}

private static byte[] hmac(byte[] key, byte[] msg) {
    Mac mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(msg)
}

private String awsTimestamp() {
    Date nowDate = new Date()
    Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
    cal.setTime(nowDate)
    
    java.text.SimpleDateFormat dowFormat = new java.text.SimpleDateFormat("EEE", java.util.Locale.US)
    java.text.SimpleDateFormat monthFormat = new java.text.SimpleDateFormat("MMM", java.util.Locale.US)
    java.text.SimpleDateFormat timeFormat = new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
    java.text.SimpleDateFormat yearFormat = new java.text.SimpleDateFormat("yyyy", java.util.Locale.US)
    
    dowFormat.setTimeZone(TimeZone.getTimeZone("UTC"))
    monthFormat.setTimeZone(TimeZone.getTimeZone("UTC"))
    timeFormat.setTimeZone(TimeZone.getTimeZone("UTC"))
    yearFormat.setTimeZone(TimeZone.getTimeZone("UTC"))
    
    String dow = dowFormat.format(nowDate)
    String month = monthFormat.format(nowDate)
    int day = cal.get(Calendar.DAY_OF_MONTH)
    String time = timeFormat.format(nowDate)
    String year = yearFormat.format(nowDate)
    
    return "${dow} ${month} ${day} ${time} UTC ${year}"
}

private static String bytesToHex(byte[] b) {
    StringBuilder sb = new StringBuilder(b.length * 2)
    for (int i = 0; i < b.length; i++) {
        int v = b[i] & 0xFF
        if (v < 16) sb.append('0')
        sb.append(Integer.toHexString(v))
    }
    return sb.toString()
}

private static byte[] hexToBytes(String hex) {
    String h = (hex ?: "").replaceAll("\\s","")
    int len = h.length()
    byte[] out = new byte[len/2]
    for (int i = 0; i < len; i += 2) {
        out[i/2] = (byte) Integer.parseInt(h.substring(i, i+2), 16)
    }
    return out
}

private static byte[] concatBytes(byte[] a, byte[] b) {
    byte[] out = new byte[a.length + b.length]
    for (int i = 0; i < a.length; i++) {
        out[i] = a[i]
    }
    for (int i = 0; i < b.length; i++) {
        out[a.length + i] = b[i]
    }
    return out
}

/* =========================
 * Logging
 * ========================= */

private void logDebug(msg) { if (debugLogging) log.debug "[MysaApp] ${msg}" }
private void logInfo(msg) { log.info "[MysaApp] ${msg}" }
private void logWarn(msg) { log.warn "[MysaApp] ${msg}" }
